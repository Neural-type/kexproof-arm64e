#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "primitives_external.h"

#define BIT(b)    (1ULL << (b))
#define ONES(x)          (BIT((x))-1)
#define PAC_MASK kconstant(pointer_mask)
#define SIGN(p)          ((p) & BIT(55))
#define UNSIGN_PTR(p)    (SIGN(p) ? ((p) | PAC_MASK) : ((p) & ~PAC_MASK))

// PAC strip for stored pointers on 18.6/T8122. The upstream UNSIGN_PTR
// (bit55 + pointer_mask) does NOT remove the tags seen on this device
// (e.g. SPTMArgs[0] = 0x71857ff0486e4fc0, true VA 0xfffffff0486e4fc0).
// T1SZ_BOOT = 0x11 -> 47-bit VAs: keep bits 0..46, sign-extend bit 46.
// Verified against the live dump (cpu_ttep, gVirtBase, libsptm_* pointees,
// and zone-map pointers pass through unchanged).
static inline uint64_t kp_untag_ptr(uint64_t p)
{
	p &= 0x00007fffffffffffULL;
	if (p & (1ULL << 46)) p |= 0xffff800000000000ULL;
	return p;
}

typedef enum
{
	KALLOC_OPTION_GLOBAL, // Global Allocation, never manually freed
	KALLOC_OPTION_LOCAL, // Allocation attached to this process, freed on process exit
} kalloc_options;

void enumerate_pages(uint64_t start, size_t size, uint64_t pageSize, bool (^block)(uint64_t, size_t));

int kreadbuf(uint64_t kaddr, void* output, size_t size);
int kwritebuf(uint64_t kaddr, const void* input, size_t size);
// Diagnostic read variant with the 0x20 window aligned down and the correct
// sub-offset — used by the dump self-test to compare against the stock path.
void early_kreadbuf_aligned(uint64_t where, void *readBuf, size_t size);
int physreadbuf(uint64_t physaddr, void* output, size_t size);
int physwritebuf(uint64_t physaddr, const void* input, size_t size);
int vreadbuf(uint64_t tte_p, const void *addr, void *outdata, size_t datalen);
int vwritebuf(uint64_t tte_p, const void *addr, const void *indata, size_t datalen);
int proc_vreadbuf(uint64_t proc, const void *addr, void *outdata, size_t datalen);
int proc_vwritebuf(uint64_t proc, const void *addr, const void *indata, size_t datalen);

uint64_t physread64(uint64_t pa);
uint64_t physread_ptr(uint64_t va);
uint32_t physread32(uint64_t pa);
uint16_t physread16(uint64_t pa);
uint8_t physread8(uint64_t pa);

int physwrite64(uint64_t pa, uint64_t v);
int physwrite32(uint64_t pa, uint32_t v);
int physwrite16(uint64_t pa, uint16_t v);
int physwrite8(uint64_t pa, uint8_t v);

uint64_t kread64(uint64_t va);
uint64_t kread_ptr(uint64_t va);
uint64_t kread_smrptr(uint64_t va);
uint32_t kread32(uint64_t va);
uint16_t kread16(uint64_t va);
uint8_t kread8(uint64_t va);

int kwrite64(uint64_t va, uint64_t v);
int kwrite_ptr(uint64_t kaddr, uint64_t pointer, uint16_t salt);
int kwrite32(uint64_t va, uint32_t v);
int kwrite16(uint64_t va, uint16_t v);
int kwrite8(uint64_t va, uint8_t v);

int physaccess_mapped(uint64_t pa, uint64_t size, kernel_map_accessor accessorBlock);
int kaccess_mapped(uint64_t va, uint64_t size, kernel_map_accessor accessorBlock);

int kcall(uint64_t *result, uint64_t func, int argc, const uint64_t *argv);
int kexec(kRegisterState *state);

int kmap(uint64_t pa, uint64_t size, void **uaddr);
int kalloc_with_options(uint64_t *addr, uint64_t size, kalloc_options options);
int kalloc(uint64_t *addr, uint64_t size);

int kfree(uint64_t addr, uint64_t size);

bool is_kcall_available(void);

#endif
