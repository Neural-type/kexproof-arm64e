#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Builds the kernel dump report as plain text. Requires the ClearSword
// primitives to be live (gPrimitives.kreadbuf) and gSystemInfo to be
// populated (XPF dynamic offsets + hardcoded ladders). Every symbol lookup is
// guarded: missing keys and untranslatable addresses are logged and skipped,
// never dereferenced blindly.
@interface KPDump : NSObject

// Resolve a mach thread port to its kernel thread_t VA (TaskRop helper).
+ (uint64_t)rcResolveThreadKVA:(mach_port_t)port;

// Boot constants + EXP-02 harvest: fills
// kernelConstant.base/virtBase/physBase/physSize/cpuTTEP (PAC-stripped, with
// cpu_ttep kept as TTBR phys per field data) and, when derivable,
// sptmBase/sptmSlide/txmBase/txmSlide. Only the EL2 SPTM/TXM image domain
// (0xfffffff01…/0xfffffff02…) is never read — it panics on touch.
+ (void)initializeBootConstantsGuarded;

// Full dump. Returns the report text (also streamed to KPLog as it builds).
+ (NSString *)buildReport;

// Experiment (A0): safe write proof — same-value rewrite on mach_kobj_count.
// Never panics; PASS proves kwrite works end-to-end.
+ (NSString *)sptmWriteTestReport;

// Experiment (A1): frame_table write — MAY PANIC. Only meaningful after A0
// passes. Scans for a zero entry, writes a marker, reads back, restores.
+ (NSString *)sptmFrameTableWriteTestReport;

// EXP-01: resolve the real allproc list head. Tries, in order: an alternate
// static pair for this kernelcache, the XPF anchor pair, an anchor-drift
// scan, then a zone-name route from our corrupted inpcb (content-calibrated).
// Returns the head whose chain contains pid 0 / "kernel_task", or 0.
+ (uint64_t)resolveAllprocHeadWithLog:(nullable NSMutableString *)log;

// Walk the resolved chain to a pid (pid offset is calibrated, see below).
+ (uint64_t)findProcByPid:(uint32_t)pid log:(nullable NSMutableString *)log;

// Walk the resolved chain matching our own comm — independent of p_pid.
+ (uint64_t)findSelfProcByComm:(nullable NSMutableString *)log;

// Calibrate p_pid against kernel_task=0 / launchd=1 / self=getpid().
+ (void)calibratePidOffset:(nullable NSMutableString *)log;

// Zone-name fallback: inpcb → zone("inpcb") → zone("proc") → our proc,
// validated by the proc_ro→ucred→cr_uid == getuid() hop.
+ (uint64_t)zoneRouteSelfProcWithLog:(nullable NSMutableString *)log;

// EXP-02: scan the 16 tagged pointers at SPTMArgs for the DEBG debug header
// and recover SPTM/TXM runtime bases+slides; falls back to a pointer-vote
// derivation over the libsptm shared pages. Idempotent.
+ (BOOL)harvestSptmTxmBasesWithLog:(nullable NSMutableString *)log;

// Stripped pointee VAs of the libsptm kernel block (cached).
+ (NSArray<NSNumber *> *)libsptmBlockPointeesWithLog:(nullable NSMutableString *)log;

// Slide derivation by pointer voting against known SPTM/TXM static offsets.
+ (BOOL)deriveSptmTxmSlidesByVote:(nullable NSMutableString *)log;

// EXP-01..03 survey report: fixed allproc walk, debug-header harvest,
// frame-table + 63 frame-type descriptors + PAPT ranges, calibrated
// frame-type enum and the writability predicate. Read-only.
+ (NSString *)sptmSurveyReport;

// EXP-09: forge a ucred (uid/gid 0, NULL MAC label, bumped refcount) in a
// pipe buffer (XNU_DEFAULT heap we control), then swap our proc's
// proc_ro->p_ucred pointer at it. Frame-type pre-filter gates the write.
// The forged object is never freed and the original pointer is only logged.
+ (NSString *)ucredHeapSwapReport;

// E10: task-port theft — sandbox escape via data-only heap write. Allocates
// our own mach port (RW-heap ipc_port), walks our itk_space
// (task → is_table (SMR) → entry → ie_object) to its kernel VA, finds launchd
// by the fast pid-walk (pid 1 → proc_ro → pr_task), then rewrites OUR port's
// ip_kobject → launchd task_t and io_bits kotype → IKOT_TASK. Verified from
// userspace (pid_for_task == 1, mach_vm_region / mach_vm_read on launchd),
// then restored and destroyed. The only object ever written is our own port;
// launchd's task is read-only. Transient by design: a forged task-kotype port
// destroyed at app exit would run the task teardown path on launchd's task
// (refcount underflow → panic), so the original io_bits/ip_kobject are
// written back in place before mach_port_destroy.
+ (NSString *)taskPortTheftReport;

// E11: proc_ro-swap → root + unsandbox. Replaces the dead EXP-09 ucred-swap
// (proc_ro lives in the RO zone on 18.6 — field writes never land) and E10.
// Swaps the proc_ro POINTER itself: proc->p_proc_ro is a RAW pointer (no PAC,
// device-log confirmed) in the writable proc zone. Our proc_ro is copied
// whole (0x400) into our own wired user page (EXP-09 1.9.3 physmap path:
// posix_memalign + mlock + vtophys via our pmap + phystokv → kernel VA),
// then ONLY p_ucred (SMR qword verbatim — value-level portable, no decode)
// and p_csflags (u32) are overlaid from launchd's proc_ro (read-only, never
// written). Device finding (18.6): task_tokens and the filter-mask pointers
// are PAC-signed with address diversity — copied to a different address they
// fail DA-key authentication (panic at verify), so they stay ours. One
// 8-byte heap write points p_proc_ro at the forge; verify is getuid()==0 +
// a /private/var/root write probe. p_proc_ro is restored to its original raw
// value immediately after verify — the forged proc_ro references launchd's
// ucred without a ref, so exit/exec while swapped = ucred refcount
// underflow = panic.
+ (NSString *)procRoSwapReport;

// PHYSMAP-WRITE: пишется ли userland-страница через physmap kernel VA —
// ключевой тест для подмены данных процессов (камера/сенсоры/геолокация/
// Ghost). Своя wired-страница (posix_memalign + mlock), маркеры 0xAA…/0xBB…
// из юзерспейса, цепь 1.9.3 (proc→proc_ro→task→map→pmap→ttep→vtophys по
// нашему pmap→phystokv → kernel VA), одна 8-байтная kwritebuf по physmap
// VA (0x4141414141414141 в голову), вердикт читается ИЗ ЮЗЕРСПЕЙСА той же
// страницы. Обратная проверка: user-write 0x42… в середину → physmap read.
// Плюс frame-type диагностика фрейма страницы (XNU_DEFAULT?).
+ (NSString *)physmapWriteUserTestReport;

// GART recon: IOGPU user client → IOGPUDevice → IOGPU → дамп pointer-полей
// (охота за AGXSecureGart). Read-only.
+ (NSString *)gartProbeReport;

// D1: TXM stack recon (kread-only). Finds thread_t via the thread port,
// dumps every kernel-VA field with its page's frame type, hunts the 0x2a
// (TXM stack) page to learn the txm_stack offset empirically, calibrates the
// frame-type enum against known anchors, and samples 4096 FTEs for type-0
// pages (retype 0 → ANY by the descriptor matrix).
+ (NSString *)txmStackReconReport;

// CVE-2026-28992: IOHIDFamily FastPathUserClient UAF race (close vs
// copyEvent across 15 conns + 8 copy threads). May panic (MTE tag fault) —
// the panic IS the confirmation. Unpatched on 18.6.
+ (NSString *)hidUafReport;

// NECP flow UAF probe (natsuk1 vector): exhaust flows, drop gated flow,
// pipe-spray fake flow, copy_result. Stage 2: fake flow assigned_addr =
// kernel base → arbitrary kread, verified by magic 0xfeedfacf. Independent
// of ClearSword.
+ (NSString *)necpUafProbeReport;

// M2Scaler CVE-2025-43510 COW race + CVE-2026-43655 OOB sweep (PoC v3 port):
// probe sel 0-15, MultiPlaneDescriptor boundary sweep sel 5-7 (KASLR leak
// detection), then COW remap race 50k iters × 12 flippers. May reboot — the
// reboot inside the race IS the COW-vulnerability confirmation.
+ (NSString *)m2CowRaceReport;

// CVE-2026-20687: AppleJPEGDriver startDecoder UAF. victim submits async
// decodes and closes (stale queue ptrs), reclaim recycles the freed
// JpegRequest slots, sync trigger drives the timeout path. asyncToken lands
// at req+16 — visible to our marker hunt. May panic (MTE tag fault) — the
// panic IS the confirmation. Unpatched on 18.6.
+ (NSString *)jpegUafReport;

// IOSurfaceRootUserClient surface map: open IOSurfaceRoot, call selectors
// 0-63 with empty/0x58/0x1000 feeds, log kr per method. Reveals which
// methods exist (not-Unsupported) for the reverse phase.
+ (NSString *)iosurfaceProbeReport;

// IOSurface backing-PA swap: overwrite ranges[0].pa of a surface in its
// writable kernel object (+0x360/+0x3a4 per the interface doc), then submit
// the scaler — the DMA engine writes into the swapped page. Control page
// first (pixels must land), then a protected page to test DART validation.
+ (NSString *)iosurfacePaSwapReport;

// Binary check that the Plume sideloader granted the lara entitlements:
// fork (no-sandbox), AGXDevice, HID virtual device, tcc file access.
+ (NSString *)entitlementsTestReport;

// PAC forging test (TaskRop remotepac port): sign a test pointer with our
// own thread's PAC keys through a hijacked pacthread, verify it matches the
// userland pacia result. VERIFIED = PAC forging works → kcall path opens.
+ (NSString *)pacTestReport;

// M2Scaler probe: чистый userland IOKit тест — KRW НЕ нужен. Проверяет,
// виден ли AppleM2ScalerCSCDriver из app sandbox и открывается ли
// IOServiceOpen (type 0 / type 1). Reachable = CVE-2025-43510/43655
// эксплуатируемы прямо из нашего приложения. Безопасно: только open/close.
+ (NSString *)m2ScalerReachabilityReport;

// M2Scaler teardown UAF (CVE-2026-43655): чистый userland IOKit, KRW НЕ
// нужен. ДЕСТРУКТИВНО — успех это паника: 50 async-опов с credit 0xDEAD0001 →
// IOServiceClose(victim) → спрей 50 коннекшенов с credit 0xBEEF0002 →
// 100 раундов × 50 async-опов на спрее, параллельно CADisplayLink-триггер
// каждый кадр переписывает пиксели IOSurface и переназначает её как contents
// видимого CALayer (программная замена «tap Dynamic Island» из PoC).
// Маркер в x9 паник-лога показывает,
// чью память прочитал scheduler (0xBEEF0002 = UAF на спрей). Дожили до конца
// без паники = баг не сработал в этом прогоне, повторить.
+ (NSString *)m2ScalerUafReport;

// EXP-13: nest/unnest race rig — MAY PANIC (by design). Walks to our pmap's
// nested subordinate (shared cache), picks one live twig page-table frame,
// then races 4 fork/_exit churn threads against a ~30 ms poll of that twig's
// frame-table entry. Any type/level/owner/rw_guard desync against the
// baseline is sync-logged before a possible panic; the win shape is
// FTE.type == XNU_DEFAULT (0x0b) while the grand pmap's twig TTE is alive.
+ (NSString *)sptmNestRaceReport;

@end

NS_ASSUME_NONNULL_END
