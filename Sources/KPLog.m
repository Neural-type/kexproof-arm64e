#import "KPLog.h"
#import "KPRunner.h"

#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <os/log.h>
#import <stdio.h>
#import <string.h>

// File-scope so the C-side direct writer (KPLogDirect) can reach it:
// exploit-stage lines must hit the disk synchronously, before a panic can
// leave them stranded in the pipe/queue.
static NSString *gKPLivePath = nil;
static NSFileHandle *gKPLiveHandle = nil;
static BOOL gKPRotationDone = NO;

static void KPReportLogFailure(NSString *message) {
    // Never send errors from this sink back through KPLog.
    os_log_error(OS_LOG_DEFAULT, "[KexProof] live log: %{public}s", message.UTF8String);
}

static BOOL KPOpenLiveLog(void) {
    if (gKPLiveHandle) return YES;
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    if (!gKPLivePath) gKPLivePath = [docs stringByAppendingPathComponent:@"kexproof-live.log"];
    NSError *directoryError = nil;
    if (![[NSFileManager defaultManager] createDirectoryAtPath:docs withIntermediateDirectories:YES attributes:nil error:&directoryError]) {
        KPReportLogFailure(directoryError.localizedDescription);
        return NO;
    }
    if (!gKPRotationDone) {
        NSString *prevPath = [docs stringByAppendingPathComponent:@"kexproof-prev.log"];
        // Atomic replacement keeps the old live file intact if rotation fails.
        if (rename(gKPLivePath.fileSystemRepresentation, prevPath.fileSystemRepresentation) != 0 && errno != ENOENT) {
            int error = errno;
            KPReportLogFailure([NSString stringWithFormat:@"rotation: %s", strerror(error)]);
            return NO;
        }
        gKPRotationDone = YES;
    }
    int fd = open(gKPLivePath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        int error = errno;
        KPReportLogFailure([NSString stringWithFormat:@"open: %s", strerror(error)]);
        return NO;
    }
    gKPLiveHandle = [[NSFileHandle alloc] initWithFileDescriptor:fd closeOnDealloc:YES];
    int dfd = open(docs.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
    return YES;
}

// 1.2.7: synchronous, queue-free, panic-proof line write for the C exploit code.
// 1.4.6: the race-flood prefixes are batched (they are what triggered the
// diskwrites_resource jetsam at thousands/sec); every OTHER line fsyncs
// immediately, so a panic can never eat the forensic tail again — the 1.4.5
// flat 200ms batch lost exactly the lines that mattered.
static bool kpLineIsRaceFlood(const char *line) {
    return strncmp(line, "[race]", 6) == 0 ||
           strstr(line, "read race sync timeout") ||
           strstr(line, "mid-scan spray") ||
           strstr(line, "spray_socket");
}
// Called under the class lock by both producers. Reopening appends to the same
// session; a transient write failure must not rotate or truncate that session.
static BOOL KPWriteLiveLine(NSString *line) {
    if (!KPOpenLiveLog()) return NO;
    static NSTimeInterval lastSync = 0;
    @try {
        [gKPLiveHandle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
        if (!kpLineIsRaceFlood(line.UTF8String) || now - lastSync >= 0.5) {
            [gKPLiveHandle synchronizeFile];
            lastSync = now;
        }
        return YES;
    } @catch (NSException *exception) {
        @try { [gKPLiveHandle closeFile]; } @catch (NSException *ignored) {}
        gKPLiveHandle = nil;
        KPReportLogFailure(exception.reason ?: exception.name);
        return NO;
    }
}

void KPLogDirect(const char *line) {
    if (!line || !*line) return;
    NSString *text = [[NSString alloc] initWithUTF8String:line];
    if (!text) return;
    @synchronized ([KPLog class]) {
        KPWriteLiveLine([text hasSuffix:@"\n"] ? text : [text stringByAppendingString:@"\n"]);
    }
    // 1.5.3: the exploit thread no longer writes to the stderr pipe (a full
    // pipe blocked it in fputs/fflush right after a win). Feed the transcript
    // and the on-screen log from here instead. Race-flood lines skip the UI:
    // thousands of main-queue blocks a second would drown the app.
    if (!kpLineIsRaceFlood(line)) {
        [[KPLog shared] appendTranscriptOnly:text];
    }
}

@interface KPLog () {
    NSMutableString *_transcript;
    dispatch_queue_t _queue;
}
@end

@implementation KPLog

+ (instancetype)shared {
    static KPLog *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[KPLog alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _transcript = [[NSMutableString alloc] init];
        _queue = dispatch_queue_create("com.stealth.kexproof.log", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)append:(NSString *)text {
    if (text.length == 0) return;
    NSString *line = text;
    if (![line hasSuffix:@"\n"]) {
        line = [line stringByAppendingString:@"\n"];
    }

    // Forward each line to the pre-capture stderr: NSLog here would re-enter
    // the stdout/stderr pipe and recurse forever while capture is active.
    for (NSString *part in [[line stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]] componentsSeparatedByString:@"\n"]) {
        KPForwardToOriginalStderr([NSString stringWithFormat:@"[KexProof] %@", part]);
        // 1.4.7: NSLog mirrors only NON-flood lines. Mirroring the race flood
        // made logd backpressure block the pipe reader, which hung
        // kpStopCapture's pthread_join and let the watchdog kill the app
        // right after a successful exploit — the post-guard death window.
        if (!kpLineIsRaceFlood(part.UTF8String)) {
            os_log(OS_LOG_DEFAULT, "[KexProof] %{public}s", part.UTF8String);
        }
    }

    // 1.4.8: persist to the live file SYNCHRONOUSLY on the caller's thread —
    // an app death used to strand stage/beat lines in the async queue ("3/4
    // on screen, empty in the file"). The class lock already serializes
    // writers; race-flood lines share KPLogDirect's batched fsync rule.
    @synchronized ([KPLog class]) {
        KPWriteLiveLine(line);
    }

    dispatch_async(_queue, ^{
        [_transcript appendString:line];
        // 1.2.4: cap the in-memory transcript — an unbounded NSMutableString
        // plus the exploit's ~1GB of mappings invites jetsam mid-race.
        if (_transcript.length > 262144) {
            [_transcript deleteCharactersInRange:NSMakeRange(0, _transcript.length - 196608)];
        }

        void (^handler)(NSString *) = self.onAppend;
        if (handler) {
            dispatch_async(dispatch_get_main_queue(), ^{
                handler(line);
            });
        }
    });
}

- (void)appendTranscriptOnly:(NSString *)text {
    if (text.length == 0) return;
    NSString *line = text;
    if (![line hasSuffix:@"\n"]) {
        line = [line stringByAppendingString:@"\n"];
    }
    // 1.5.6: mirror engine lines into the unified log as well. With KPRINTF's
    // stderr leg removed, idevicesyslog lost every engine line (win??,
    // returning 0, stage beats) — KPLogDirect only fed the file. Callers hand
    // only non-flood lines here, so logd backpressure stays bounded.
    NSLog(@"[KexProof] %@", [line stringByTrimmingCharactersInSet:[NSCharacterSet newlineCharacterSet]]);
    dispatch_async(_queue, ^{
        [_transcript appendString:line];
        if (_transcript.length > 262144) {
            [_transcript deleteCharactersInRange:NSMakeRange(0, _transcript.length - 196608)];
        }
        void (^handler)(NSString *) = self.onAppend;
        if (handler) {
            dispatch_async(dispatch_get_main_queue(), ^{
                handler(line);
            });
        }
    });
}

- (void)appendFormat:(NSString *)fmt, ... {
    va_list args;
    va_start(args, fmt);
    NSString *text = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    [self append:text];
}

- (NSString *)transcript {
    __block NSString *result = nil;
    dispatch_sync(_queue, ^{
        result = [_transcript copy];
    });
    return result;
}

@end

// 1.5.1: C-callable bridge into the full KPLog path (NSLog + synced live file).
void KPLogNSLog(const char *line) {
    if (!line || !*line) return;
    NSString *text = [[NSString alloc] initWithUTF8String:line];
    if (text) [[KPLog shared] append:text];
}
