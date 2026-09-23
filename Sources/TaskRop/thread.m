// thread.m — thread helpers port (lara thread.m) for KexProof.
#import "rc.h"
#import <mach/mach.h>

bool kp_threadsetstate(mach_port_t machthread, kp_arm_thread_state64_internal *state)
{
    kern_return_t kr = thread_set_state(machthread, ARM_THREAD_STATE64,
                                        (thread_state_t)state, ARM_THREAD_STATE64_COUNT);
    return (kr == KERN_SUCCESS);
}

void kp_threadsetpac(uint64_t threadaddr, uint64_t keya, uint64_t keyb)
{
    kp_rc_kwrite64(threadaddr + KP_OFF_THREAD_MACHINE_ROP_PID, keya);
    kp_rc_kwrite64(threadaddr + KP_OFF_THREAD_MACHINE_JOP_PID, keyb);
}
