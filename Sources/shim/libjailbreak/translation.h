#ifndef TRANSLATION_H
#define TRANSLATION_H

#include <stdint.h>
#include "pte.h"

struct tt_level {
	uint64_t offMask;
	uint64_t shift;
	uint64_t indexMask;
	uint64_t validMask;
	uint64_t typeMask;
	uint64_t typeBlock;
};
extern struct tt_level arm_tt_level[4];

uint64_t phystokv(uint64_t pa);
uint64_t vtophys_lvl(uint64_t tte_ttep, uint64_t va, uint64_t *leaf_level, uint64_t *leaf_tte_ttep);
uint64_t vtophys(uint64_t tte_ttep, uint64_t va);
uint64_t kvtophys(uint64_t va);
void libjailbreak_translation_init(void);

// KexProof: EXP-03 installs the content-hunted PAPT table here (the
// libsptm_papt_ranges symbol path can point at a stub page on 18.6).
extern uint64_t kp_papt_table_va;
extern uint64_t kp_papt_table_n;
extern uint32_t kp_papt_format;

// KexProof 1.9.177: frame-type инструмент против SPTM/EL2 ресетов. Setter
// зовётся из KPDump при резолве frame table. Список {0x13,0x14,0x17,0x37}
// неверен для нашего примитива (таблицы TTBR1 того типа ЧИТАЮТСЯ) — гейт только
// 0x37 + census типов через kpFrameTypeOf.
void kpSetFrameTableVA(uint64_t va);
int kpFrameDeadly(uint64_t pa);
int kpFrameTypeOf(uint64_t pa);
void kpSetFrameTypeLogger(void (*cb)(int, uint64_t));

// 1.9.252: адрес/уровень последней deadly-таблицы, на которой встал walker
// (форж читает её через DART-копию — CPU-чтение deadly, DMA-чтение мимо SPTM).
extern uint64_t kp_lastDeadlyTte;
extern int kp_lastDeadlyLvl;

#endif