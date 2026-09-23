// compiler-rt replacement: this toolchain lacks libclang_rt's
// __isOSVersionAtLeast. Map the Darwin version to the iOS version
// (Darwin 21->iOS 15, 22->16, 23->17, 24->18; Darwin 25->iOS 26).
#include <stdio.h>
#include <sys/sysctl.h>

int __isOSVersionAtLeast(int major, int minor, int patch) {
    char version[64] = {0};
    size_t size = sizeof(version);
    if (sysctlbyname("kern.osversion", version, &size, NULL, 0) != 0) {
        return 0;
    }
    int darwinMajor = 0;
    int darwinMinor = 0;
    int darwinPatch = 0;
    if (sscanf(version, "%d.%d.%d", &darwinMajor, &darwinMinor, &darwinPatch) < 2) {
        return 0;
    }
    int iosMajor = darwinMajor >= 25 ? darwinMajor + 1 : darwinMajor - 6;
    if (iosMajor != major) {
        return iosMajor > major;
    }
    if (darwinMinor != minor) {
        return darwinMinor > minor;
    }
    return darwinPatch >= patch;
}
