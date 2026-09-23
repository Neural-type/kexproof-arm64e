#import "KPLog.h"
#import "KPRunner.h"

#import <fcntl.h>
#import <unistd.h>

// File-scope so the C-side direct writer (KPLogDirect) can reach it:
// exploit-stage lines must hit the disk synchronously, before a panic can
// leave them stranded in the pipe/queue.
static NSString *gKPLivePath = nil;
static NSFileHandle *gKPLiveHandle = nil;

static void KPOpenLiveLog(void) {
    if (gKPLivePath) return;
    gKPLivePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-live.log"];
    // 1.2.2: rotate, never wipe — a relaunch after a panic must not
    // destroy the dead run's log. Previous session -> kexproof-prev.log.
    NSString *prevPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-prev.log"];
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:gKPLivePath]) {
        [fm removeItemAtPath:prevPath error:nil];
        [fm moveItemAtPath:gKPLivePath toPath:prevPath error:nil];
    }
    [fm createFileAtPath:gKPLivePath contents:nil attributes:nil];
    gKPLiveHandle = [NSFileHandle fileHandleForWritingAtPath:gKPLivePath];
    // 1.2.6: fsync the DIRECTORY as well — a per-line file fsync alone
    // loses the file's directory entry on kernel panic (APFS rollback),
    // which is why post-reboot shares came back empty.
    int dfd = open([[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] fileSystemRepresentation], O_RDONLY);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
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
void KPLogDirect(const char *line) {
    if (!line || !*line) return;
    static uint64_t gLastFsyncMs = 0;
    @synchronized ([KPLog class]) {
        if (!gKPLiveHandle) KPOpenLiveLog();
        @try {
            [gKPLiveHandle seekToEndOfFile];
            [gKPLiveHandle writeData:[NSData dataWithBytes:line length:strlen(line)]];
            [gKPLiveHandle writeData:[NSData dataWithBytes:"\n" length:1]];
            if (!kpLineIsRaceFlood(line)) {
                [gKPLiveHandle synchronizeFile];
            } else {
                uint64_t nowMs = (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0);
                if (nowMs - gLastFsyncMs >= 500) {
                    [gKPLiveHandle synchronizeFile];
                    gLastFsyncMs = nowMs;
                }
            }
        } @catch (NSException *ignored) {}
    }
    // 1.5.3: the exploit thread no longer writes to the stderr pipe (a full
    // pipe blocked it in fputs/fflush right after a win). Feed the transcript
    // and the on-screen log from here instead. Race-flood lines skip the UI:
    // thousands of main-queue blocks a second would drown the app.
    if (!kpLineIsRaceFlood(line)) {
        NSString *text = [[NSString alloc] initWithUTF8String:line];
        if (text) [[KPLog shared] appendTranscriptOnly:text];
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
            NSLog(@"[KexProof] %@", part);
        }
    }

    // 1.4.8: persist to the live file SYNCHRONOUSLY on the caller's thread —
    // an app death used to strand stage/beat lines in the async queue ("3/4
    // on screen, empty in the file"). The class lock already serializes
    // writers; race-flood lines share KPLogDirect's batched fsync rule.
    @synchronized ([KPLog class]) {
        if (!gKPLiveHandle) KPOpenLiveLog();
        @try {
            static NSString *gLastFileLine = nil;
            if (![line isEqualToString:gLastFileLine]) {
                gLastFileLine = [line copy];
                [gKPLiveHandle seekToEndOfFile];
                [gKPLiveHandle writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
                if (!kpLineIsRaceFlood(line.UTF8String)) {
                    [gKPLiveHandle synchronizeFile];
                } else {
                    static uint64_t gQLastFsyncMs = 0;
                    uint64_t nowMs = (uint64_t)([[NSDate date] timeIntervalSince1970] * 1000.0);
                    if (nowMs - gQLastFsyncMs >= 500) {
                        [gKPLiveHandle synchronizeFile];
                        gQLastFsyncMs = nowMs;
                    }
                }
            }
        } @catch (NSException *ignored) {}
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
