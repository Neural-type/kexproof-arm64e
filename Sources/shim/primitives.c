// KexProof local shim of Dopamine's BaseBin/libjailbreak/src/primitives.c
// Only the primitives that are cleanly separable from the jailbreak
// infrastructure are implemented: kread/kwrite dispatchers over
// gPrimitives.kreadbuf/kwritebuf, the typed convenience wrappers, and the
// physical<->virtual fallbacks (kread-based, translation.c provides
// phystokv/kvtophys). kcall/kexec/kalloc/vreadbuf/proc_* are declared in
// primitives.h but intentionally not implemented here; nothing in KexProof
// references them, so they never hit the linker.

#include <libjailbreak/primitives.h>
#include <libjailbreak/info.h>
#include <libjailbreak/translation.h>
#include <errno.h>
#include <string.h>

// From BaseBin/libjailbreak/src/util.h
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

struct kernel_primitives gPrimitives = { 0 };

// Wrappers physical <-> virtual

void enumerate_pages(uint64_t start, size_t size, uint64_t pageSize, bool (^block)(uint64_t curStart, size_t curSize))
{
	uint64_t curStart = start;
	size_t sizeLeft = size;
	bool c = true;
	while (sizeLeft > 0 && c) {
		uint64_t pageOffset = curStart & (pageSize - 1);
		uint64_t readSize = min(sizeLeft, pageSize - pageOffset);
		c = block(curStart, readSize);
		curStart += readSize;
		sizeLeft -= readSize;
	}
}

int _kreadbuf_phys(uint64_t kaddr, void* output, size_t size)
{
	memset(output, 0, size);

	__block int pr = 0;
	enumerate_pages(kaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curKaddr, size_t curSize){
		uint64_t curPhys = kvtophys(curKaddr);
		if (curPhys == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = physreadbuf(curPhys, &output[curKaddr - kaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _kwritebuf_phys(uint64_t kaddr, const void* input, size_t size)
{
	__block int pr = 0;
	enumerate_pages(kaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curKaddr, size_t curSize){
		uint64_t curPhys = kvtophys(curKaddr);
		if (curPhys == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = physwritebuf(curPhys, &input[curKaddr - kaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _physreadbuf_virt(uint64_t physaddr, void* output, size_t size)
{
	memset(output, 0, size);

	__block int pr = 0;
	enumerate_pages(physaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curPhys, size_t curSize){
		uint64_t curKaddr = phystokv(curPhys);
		if (curKaddr == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = kreadbuf(curKaddr, &output[curPhys - physaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

int _physwritebuf_virt(uint64_t physaddr, const void* input, size_t size)
{
	__block int pr = 0;
	enumerate_pages(physaddr, size, vm_real_kernel_page_size, ^bool(uint64_t curPhys, size_t curSize){
		uint64_t curKaddr = phystokv(curPhys);
		if (curKaddr == 0 && errno != 0) {
			pr = errno;
			return false;
		}
		pr = kwritebuf(curKaddr, &input[curPhys - physaddr], curSize);
		if (pr != 0) {
			return false;
		}
		return true;
	});
	return pr;
}

// Wrappers to gPrimitives

int kreadbuf(uint64_t kaddr, void* output, size_t size)
{
	if (gPrimitives.kreadbuf) {
		return gPrimitives.kreadbuf(kaddr, output, size);
	}
	else if (gPrimitives.physreadbuf && gPrimitives.vtophys) {
		return _kreadbuf_phys(kaddr, output, size);
	}
	return -1;
}

int kwritebuf(uint64_t kaddr, const void* input, size_t size)
{
	if (gPrimitives.kwritebuf) {
		return gPrimitives.kwritebuf(kaddr, input, size);
	}
	else if (gPrimitives.physwritebuf && gPrimitives.vtophys) {
		return _kwritebuf_phys(kaddr, input, size);
	}
	return -1;
}

int physreadbuf(uint64_t physaddr, void* output, size_t size)
{
	if (gPrimitives.physreadbuf) {
		return gPrimitives.physreadbuf(physaddr, output, size);
	}
	else if (gPrimitives.kreadbuf && gPrimitives.phystokv) {
		return _physreadbuf_virt(physaddr, output, size);
	}
	return -1;
}

int physwritebuf(uint64_t physaddr, const void* input, size_t size)
{
	if (gPrimitives.physwritebuf) {
		return gPrimitives.physwritebuf(physaddr, input, size);
	}
	else if (gPrimitives.kwritebuf && gPrimitives.phystokv) {
		return _physwritebuf_virt(physaddr, input, size);
	}
	return -1;
}

// Convenience Wrappers

uint64_t physread64(uint64_t pa)
{
	uint64_t v = 0;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint64_t physread_ptr(uint64_t pa)
{
	return UNSIGN_PTR(physread64(pa));
}

uint32_t physread32(uint64_t pa)
{
	uint32_t v = 0;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint16_t physread16(uint64_t pa)
{
	uint16_t v = 0;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

uint8_t physread8(uint64_t pa)
{
	uint8_t v = 0;
	physreadbuf(pa, &v, sizeof(v));
	return v;
}

int physwrite64(uint64_t pa, uint64_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite32(uint64_t pa, uint32_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite16(uint64_t pa, uint16_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

int physwrite8(uint64_t pa, uint8_t v)
{
	return physwritebuf(pa, &v, sizeof(v));
}

uint64_t kread64(uint64_t va)
{
	uint64_t v = 0;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint64_t kread_ptr(uint64_t va)
{
	return kp_untag_ptr(kread64(va));
}

uint32_t kread32(uint64_t va)
{
	uint32_t v = 0;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint16_t kread16(uint64_t va)
{
	uint16_t v = 0;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

uint8_t kread8(uint64_t va)
{
	uint8_t v = 0;
	kreadbuf(va, &v, sizeof(v));
	return v;
}

int kwrite64(uint64_t va, uint64_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite32(uint64_t va, uint32_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite16(uint64_t va, uint16_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}

int kwrite8(uint64_t va, uint8_t v)
{
	return kwritebuf(va, &v, sizeof(v));
}
