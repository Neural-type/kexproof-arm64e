// KexProof local shim of Dopamine's BaseBin/libjailbreak/src/translation.c
// Verbatim copy except the includes (kernel.h is not needed here), the VLA
// clamp and PAPT override in sptm_phystokv, and kp_untag_ptr via kread_ptr.
// kvtophys is used by the frame survey (EXP-03) to turn kernel VAs into PAs
// for frame-table indexing.

#include <libjailbreak/translation.h>
#include <libjailbreak/primitives.h>
#include <libjailbreak/info.h>
#include <errno.h>
#include <stdio.h>

struct tt_level arm_tt_level[4];

// KexProof: PAPT override. On 18.6 the libsptm_papt_ranges pointee is a stub
// page, not the ranges table, so the stock symbol path below can fail. The
// frame survey (EXP-03) content-hunts the real table from the libsptm block
// and installs it here; sptm_phystokv prefers the override when set.
uint64_t kp_papt_table_va = 0;
uint64_t kp_papt_table_n = 0;
// 0 = 24-B entries {paddr_start, va_base, page_count(u32),pad}; 1 = 16-B
// fast-path entries {va_base, start_pfn(u32)@8, count(u24)|flags(u8)@12}.
uint32_t kp_papt_format = 0;

// KexProof 1.9.143: обход таблиц через early_kread64 — единственный примитив,
// читающий все регионы (kreadbuf флаки: zone map 0xffffffdd/df… давал
// kvtophys=0 на proc_ro/IOSurface-объектах). Все вызовы kvtophys — только
// после победы эксплойта, когда сокет-пара примитива жива.
extern uint64_t early_kread64(uint64_t kaddr);

// Address translation physical <-> virtual

uint64_t sptm_phystokv(uint64_t pa)
{
	uint64_t papt_table = 0;
	uint64_t papt_table_n = 0;

	if (kp_papt_table_va && kp_papt_table_n) {
		papt_table = kp_papt_table_va;
		papt_table_n = kp_papt_table_n;
	}
	else {
		papt_table = kread_ptr(ksymbol(libsptm_papt_ranges));
		papt_table_n = kread32(kread64(ksymbol(libsptm_n_papt_ranges)));
	}

	// KexProof hardening: papt_table_n comes from kernel memory; a botched
	// read must not turn the stack VLA below into a crash. 1.9.6: raised 64 to
	// 512 — the live PAPT table holds ~95 ranges on this device, so 64 silently
	// zeroed every phystokv and killed kvtophys/E9's forge VA with it.
	if (papt_table_n == 0 || papt_table_n > 512) {
		return 0;
	}

	if (kp_papt_format == 1) {
		// 16-B fast-path format: {va_base:u64, start_pfn:u32, count:u24, flags:u8}
		for (uint64_t i = 0; i < papt_table_n; i++) {
			uint64_t entryVA = papt_table + i * 16;
			uint64_t f0 = 0;
			uint32_t startPfn = 0, rawCnt = 0;
			kreadbuf(entryVA, &f0, sizeof(f0));
			kreadbuf(entryVA + 8, &startPfn, sizeof(startPfn));
			kreadbuf(entryVA + 12, &rawCnt, sizeof(rawCnt));
			uint64_t count = rawCnt & 0xFFFFFF;
			uint64_t rangeStart = (uint64_t)startPfn * vm_real_kernel_page_size;
			uint64_t len = count * vm_real_kernel_page_size;
			if ((pa >= rangeStart) && (pa < (rangeStart + len))) {
				return f0 ? (pa - rangeStart + f0) : 0;
			}
		}
		return 0;
	}

	struct sptm_papt_entry {
		uint64_t paddr_start;
		uint64_t papt_start;
		uint64_t num_mappings;
	} sptm_papt_table[papt_table_n];

	memset(sptm_papt_table, 0, sizeof(sptm_papt_table));
	kreadbuf(papt_table, &sptm_papt_table[0], sizeof(sptm_papt_table));

	for (uint64_t i = 0; i < papt_table_n; i++) {
		struct sptm_papt_entry *curEntry = &sptm_papt_table[i];

		// Override tables use the verified 24-B format (u32 page_count at
		// +16); the stock symbol path keeps upstream's u64 num_mappings.
		uint64_t count = kp_papt_table_va ? (uint64_t)(uint32_t)curEntry->num_mappings
		                                  : curEntry->num_mappings;
		uint64_t len = count * vm_real_kernel_page_size;
		if ((pa >= curEntry->paddr_start) && (pa < (curEntry->paddr_start + len))) {
			return pa - curEntry->paddr_start + curEntry->papt_start;
		}
	}

	return 0;
}

#define PTOV_TABLE_SIZE 8
uint64_t phystokv(uint64_t pa)
{
	if (ksymbol(ptov_table)) {
		struct ptov_table_entry {
			uint64_t pa;
			uint64_t va;
			uint64_t len;
		} ptov_table[PTOV_TABLE_SIZE];
		kreadbuf(ksymbol(ptov_table), &ptov_table[0], sizeof(ptov_table));

		for (uint64_t i = 0; (i < PTOV_TABLE_SIZE) && (ptov_table[i].len != 0); i++) {
			if ((pa >= ptov_table[i].pa) && (pa < (ptov_table[i].pa + ptov_table[i].len))) {
				return pa - ptov_table[i].pa + ptov_table[i].va;
			}
		}

		return pa - kconstant(physBase) + kconstant(virtBase);
	}
	else if (ksymbol(libsptm_papt_ranges)) {
		return sptm_phystokv(pa);
	}

	return 0;
}

uint64_t vtophys_lvl(uint64_t tte_ttep, uint64_t va, uint64_t *leaf_level, uint64_t *leaf_tte_ttep)
{
	errno = 0;
	const uint64_t ROOT_LEVEL = PMAP_TT_L1_LEVEL;
	const uint64_t LEAF_LEVEL = *leaf_level;

	uint64_t pa = 0;

	bool physical = !(bool)(tte_ttep & 0xf000000000000000);

	for (uint64_t curLevel = ROOT_LEVEL; curLevel <= LEAF_LEVEL; curLevel++) {
		if (curLevel > PMAP_TT_L3_LEVEL) {
			errno = 1041;
			return 0;
		}

		struct tt_level *lvlp = &arm_tt_level[curLevel];
		uint64_t tteIndex = (va & lvlp->indexMask) >> lvlp->shift;
		uint64_t tteEntry = 0;
		if (physical) {
			uint64_t tte_pa = tte_ttep + (tteIndex * sizeof(uint64_t));
			tteEntry = early_kread64(phystokv(tte_pa));
			if (leaf_tte_ttep) *leaf_tte_ttep = tte_pa;
			if (leaf_level) *leaf_level = curLevel;
		}
		else if (gPrimitives.kreadbuf && !physical) {
			uint64_t tte_va = tte_ttep + (tteIndex * sizeof(uint64_t));
			tteEntry = early_kread64(tte_va);
			if (leaf_tte_ttep) *leaf_tte_ttep = tte_va;
			if (leaf_level) *leaf_level = curLevel;
		}
		else {
			printf("WARNING: Failed %s translation, no function to do it.\n", physical ? "physical" : "virtual");
			errno = 1043;
			return 0;
		}

		if ((tteEntry & lvlp->validMask) != lvlp->validMask) {
			errno = 1042;
			return 0;
		}

		if ((tteEntry & lvlp->typeMask) == lvlp->typeBlock) {
			// Found block mapping, no matter what level we are in, this is the end
			return ((tteEntry & ARM_TTE_PA_MASK & ~lvlp->offMask) | (va & lvlp->offMask));
		}

		if (physical) {
			tte_ttep = tteEntry & ARM_TTE_TABLE_MASK;
		}
		else {
			tte_ttep = phystokv(tteEntry & ARM_TTE_TABLE_MASK);
		}
	}

	// If we end up here, it means we did not find a block mapping
	// In this case, return the last page table address we traversed
	return tte_ttep;
}

uint64_t vtophys(uint64_t tte_ttep, uint64_t va)
{
	uint64_t level = PMAP_TT_L3_LEVEL;
	return vtophys_lvl(tte_ttep, va, &level, NULL);
}

uint64_t kvtophys(uint64_t va)
{
	return vtophys(kconstant(cpuTTEP), va);
}

void libjailbreak_translation_init(void)
{
	// A9+: Kernel uses 16K pages
	if (vm_real_kernel_page_size == 0x4000) {
		arm_tt_level[0] = (struct tt_level){
			.offMask = ARM_16K_TT_L0_OFFMASK,
			.shift = ARM_16K_TT_L0_SHIFT,
			.indexMask = ARM_16K_TT_L0_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[1] = (struct tt_level){
			.offMask = ARM_16K_TT_L1_OFFMASK,
			.shift = ARM_16K_TT_L1_SHIFT,
			.indexMask = kconstant(ARM_TT_L1_INDEX_MASK),
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[2] = (struct tt_level){
			.offMask = ARM_16K_TT_L2_OFFMASK,
			.shift = ARM_16K_TT_L2_SHIFT,
			.indexMask = ARM_16K_TT_L2_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[3] = (struct tt_level){
			.offMask = ARM_16K_TT_L3_OFFMASK,
			.shift = ARM_16K_TT_L3_SHIFT,
			.indexMask = ARM_16K_TT_L3_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_L3BLOCK,
		};
	}
	// A8: Kernel uses 4k pages
	else if (vm_real_kernel_page_size == 0x1000) {
		arm_tt_level[0] = (struct tt_level){
			.offMask = ARM_4K_TT_L0_OFFMASK,
			.shift = ARM_4K_TT_L0_SHIFT,
			.indexMask = ARM_4K_TT_L0_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[1] = (struct tt_level){
			.offMask = ARM_4K_TT_L1_OFFMASK,
			.shift = ARM_4K_TT_L1_SHIFT,
			.indexMask = kconstant(ARM_TT_L1_INDEX_MASK),
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[2] = (struct tt_level){
			.offMask = ARM_4K_TT_L2_OFFMASK,
			.shift = ARM_4K_TT_L2_SHIFT,
			.indexMask = ARM_4K_TT_L2_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_BLOCK,
		};
		arm_tt_level[3] = (struct tt_level){
			.offMask = ARM_4K_TT_L3_OFFMASK,
			.shift = ARM_4K_TT_L3_SHIFT,
			.indexMask = ARM_4K_TT_L3_INDEX_MASK,
			.validMask = ARM_TTE_VALID,
			.typeMask = ARM_TTE_TYPE_MASK,
			.typeBlock = ARM_TTE_TYPE_L3BLOCK,
		};
	}

	gPrimitives.phystokv = phystokv;
	gPrimitives.vtophys  = vtophys;
}
