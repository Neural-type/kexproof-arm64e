// exc.m — exception port helpers port (lara exc.m) for KexProof.
#import "rc.h"
#import <mach/mach.h>
#import <string.h>
#import <stdio.h>

mach_port_t kp_createexcport(void)
{
    mach_port_options_t options = {
        .flags = MPO_INSERT_SEND_RIGHT | 0x8000, // MPO_PROVISIONAL_ID_PROT_OPTOUT
        .mpl   = { .mpl_qlimit = 0 }
    };
    mach_port_t excport = MACH_PORT_NULL;
    kern_return_t kr = mach_port_construct(mach_task_self_, &options, 0, &excport);
    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    return excport;
}

bool kp_waitexc(mach_port_t excport, kp_excmsg *excbuf, int timeout)
{
    kern_return_t kr = mach_msg(&excbuf->Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                KP_EXC_MSG_SIZE, excport, timeout, MACH_PORT_NULL);
    return (kr == KERN_SUCCESS);
}

bool kp_statereply(kp_excmsg *exc, kp_arm_thread_state64_internal *state)
{
    uint8_t replybuf[KP_EXC_REPLY_SIZE];
    memset(replybuf, 0, sizeof(replybuf));
    kp_excreply *reply = (kp_excreply *)replybuf;

    reply->Head.msgh_bits        = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply->Head.msgh_size        = KP_EXC_REPLY_SIZE;
    reply->Head.msgh_remote_port = exc->Head.msgh_remote_port;
    reply->Head.msgh_local_port  = MACH_PORT_NULL;
    reply->Head.msgh_id          = exc->Head.msgh_id + 100;
    reply->NDR                   = exc->NDR;
    reply->RetCode               = 0;
    reply->flavor                = ARM_THREAD_STATE64;
    reply->new_stateCnt          = ARM_THREAD_STATE64_COUNT;
    memcpy(&reply->threadState, state, sizeof(kp_arm_thread_state64_internal));

    kern_return_t kr = mach_msg((mach_msg_header_t *)replybuf, MACH_SEND_MSG,
                                KP_EXC_REPLY_SIZE, 0, MACH_PORT_NULL,
                                MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return (kr == KERN_SUCCESS);
}
