// rc.m — KRW proxies for the TaskRop port.
#import "rc.h"
#import <string.h>

extern void kreadbuf(uint64_t kaddr, void *output, uint64_t size);
extern void kwritebuf(uint64_t kaddr, const void *input, uint64_t size);

void kp_rc_kread(uint64_t addr, void *out, size_t size)
{
    memset(out, 0, size);
    kreadbuf(addr, out, size);
}

void kp_rc_kwrite(uint64_t addr, const void *in, size_t size)
{
    kwritebuf(addr, in, size);
}

uint64_t kp_rc_kread64(uint64_t addr)
{
    uint64_t v = 0;
    kp_rc_kread(addr, &v, sizeof(v));
    return v;
}

uint32_t kp_rc_kread32(uint64_t addr)
{
    uint32_t v = 0;
    kp_rc_kread(addr, &v, sizeof(v));
    return v;
}

uint16_t kp_rc_kread16(uint64_t addr)
{
    uint16_t v = 0;
    kp_rc_kread(addr, &v, sizeof(v));
    return v;
}

void kp_rc_kwrite64(uint64_t addr, uint64_t v)
{
    kp_rc_kwrite(addr, &v, sizeof(v));
}

void kp_rc_kwrite32(uint64_t addr, uint32_t v)
{
    kp_rc_kwrite(addr, &v, sizeof(v));
}

void kp_rc_kwrite16(uint64_t addr, uint16_t v)
{
    kp_rc_kwrite(addr, &v, sizeof(v));
}
