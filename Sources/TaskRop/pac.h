// pac.h — PAC forging port (lara pac.m) for KexProof.
#ifndef KP_PAC_H
#define KP_PAC_H

#import <stdint.h>
#import <stdbool.h>
#import <mach/mach.h>

uint64_t kp_pac_nativestrip(uint64_t address);
uint64_t kp_pacia(uint64_t ptr, uint64_t modifier);
uint64_t kp_ptrauthstrdisc(const char *name);
bool kp_pacsignworks(void);
uint64_t kp_findpacia(void);
uint64_t kp_remotepac(uint64_t remotethreadaddr, uint64_t address, uint64_t modifier);

#endif /* KP_PAC_H */
