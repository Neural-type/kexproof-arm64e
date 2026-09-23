//
//  ClearSword.m — engine adapter (1.3.0: DarkSword engine swap)
//
//  KPRunner's contract is unchanged: exploit_init() runs the exploit, and on
//  success gPrimitives.kreadbuf/kwritebuf are live, gSystemInfo.kernelConstant
//  .slide holds the kernel slide, and krwMinSafeReadSize is 0x20.
//

#import <UIKit/UIKit.h>
#import <string.h>
#import <mach/mach.h>

// Shim FIRST: the engine's krw.h remaps its typed accessors to ds_* — the
// macro must not be active while the shim's struct kernel_primitives is parsed.
#import <libjailbreak/info.h>
#import <libjailbreak/primitives_external.h>

#import "exploit/kexploit_opa334.h"   // kexploit_opa334(), g_kernel_slide, darksword_*_pcb()
#import "exploit/krw.h"              // the engine's typed r/w (renamed ds_* by the remap)
#import "exploit/klog.h"             // KPLogDirect routing

// Restore the shim's names for the gPrimitives wiring below; the engine's
// primitives are called by their post-remap (ds_*) names from here on.
#undef kreadbuf
#undef kwritebuf
#undef kread16
#undef kread32
#undef kread64
#undef kread8
#undef kwrite8
#undef kwrite16
#undef kwrite32
#undef kwrite64
#undef kread_ptr
#undef kread_smrptr

// shim signature is int(uint64_t, void*, size_t); the engine's block readers
// return void and take uint64_t len.
static int ds_kread_shim(uint64_t kaddr, void *output, size_t size)
{
    ds_kreadbuf(kaddr, output, (uint64_t)size);
    return 0;
}

static int ds_kwrite_shim(uint64_t kaddr, const void *input, size_t size)
{
    ds_kwritebuf(kaddr, input, (uint64_t)size);
    return 0;
}

int exploit_init(const char *flavor)
{
    (void)flavor;
    int r = kexploit_opa334();
    if (r != 0) return r;

    gPrimitives.kreadbuf = ds_kread_shim;
    gPrimitives.kwritebuf = ds_kwrite_shim;

    gSystemInfo.kernelConstant.slide = g_kernel_slide;
    gPrimitives.krwMinSafeReadSize = 0x20;

    return 0;
}

int exploit_deinit(void)
{
    return 0;
}

// shim/libjailbreak/primitives.h declares this diagnostic read; the old engine
// implemented it and KPDump's self-test calls it. Same semantics over the new
// engine: read the 0x20-ALIGNED window containing `where`, index by sub-offset.
void early_kreadbuf_aligned(uint64_t where, void *readBuf, size_t size)
{
    if (size > 0x20) return;
    uint64_t target = where & ~0x1FULL;
    // never reach back across a page start
    if ((target / vm_page_size) != (where / vm_page_size)) target = where;
    size_t sub = (size_t)(where - target);
    if (sub + size > 0x20) return;
    uint8_t tmp[0x20];
    memset(tmp, 0, sizeof(tmp));
    ds_kreadbuf(target, tmp, (uint64_t)sizeof(tmp));
    memcpy(readBuf, tmp + sub, size);
}
