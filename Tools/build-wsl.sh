#!/usr/bin/env bash
set -euo pipefail

: "${THEOS:?Set THEOS to your Theos directory}"

KP_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
KP_PROJECT_DIR="$(cd -- "${KP_SCRIPT_DIR}/.." && pwd -P)"
KP_BUILD_DIR="$(mktemp -d /tmp/kexproof-build.XXXXXX)"
KP_IPA_DIR="$(mktemp -d /tmp/kexproof-ipa.XXXXXX)"
KP_OUTPUT_DIR="${KP_PROJECT_DIR}/packages"
KP_PACKAGE_VERSION="1.9.58"
KP_PACKAGE_NAME="com.stealth.kexproof_${KP_PACKAGE_VERSION}_iphoneos-arm64.deb"
KP_IPA_NAME="KexProof-${KP_PACKAGE_VERSION}.ipa"

kp_cleanup() {
    case "${KP_BUILD_DIR}" in
        /tmp/kexproof-build.*) rm -rf -- "${KP_BUILD_DIR}" ;;
        *) printf 'Refusing to remove unexpected path: %s\n' "${KP_BUILD_DIR}" >&2 ;;
    esac
    case "${KP_IPA_DIR}" in
        /tmp/kexproof-ipa.*) rm -rf -- "${KP_IPA_DIR}" ;;
        *) printf 'Refusing to remove unexpected path: %s\n' "${KP_IPA_DIR}" >&2 ;;
    esac
}
trap kp_cleanup EXIT

rsync -a --exclude '.theos' --exclude 'packages' \
    "${KP_PROJECT_DIR}/" "${KP_BUILD_DIR}/"

# module cache breaks on every arch/flag change (signature mismatch) — wipe it
# so -fmodules never sees a stale .pcm.
rm -rf /home/bobinskij/.cache/clang 2>/dev/null || true
test "$(awk '$1 == "Version:" { print $2 }' "${KP_BUILD_DIR}/control")" = \
    "${KP_PACKAGE_VERSION}"

find "${KP_BUILD_DIR}" -type d -exec chmod 755 {} +
chmod 644 \
    "${KP_BUILD_DIR}/control" \
    "${KP_BUILD_DIR}/Resources/Info.plist"
chmod 755 \
    "${KP_BUILD_DIR}/layout/DEBIAN/postinst"

env THEOS="${THEOS}" make -C "${KP_BUILD_DIR}" clean package FINALPACKAGE=1

test -x "${KP_BUILD_DIR}/.theos/_/var/jb/Applications/KexProof.app/KexProof"
test -f "${KP_BUILD_DIR}/.theos/_/var/jb/Applications/KexProof.app/Info.plist"

# the old clang 11 emits cpusubtype 0x2 (legacy arm64e, no ptrauth ABI) —
# iOS/the installer rejects it ("Failed to find matching arch"). Patch the
# subtype to 0x80000002 (arm64e + ptrauth ABI v1) and re-sign with ldid.
KP_BIN="${KP_BUILD_DIR}/.theos/_/var/jb/Applications/KexProof.app/KexProof"
python3 - "${KP_BIN}" <<'EOF'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p,'rb').read())
cputype, subtype = struct.unpack('<II', d[4:12])
if cputype == 0x100000C and subtype == 0x2:
    struct.pack_into('<I', d, 8, 0x80000002)
    open(p,'wb').write(d)
    print('cpusubtype patched to 0x80000002')
else:
    print(f'cpusubtype already {subtype:#x}, no patch')
EOF
LDID="${THEOS}/bin/ldid"
if [ -x "${LDID}" ]; then
    "${LDID}" "-S${KP_BUILD_DIR}/Resources/entitlements.plist" "${KP_BIN}"
fi

mkdir -p "${KP_OUTPUT_DIR}"
dpkg-deb -Zzstd --root-owner-group --build \
    "${KP_BUILD_DIR}/.theos/_" \
    "${KP_OUTPUT_DIR}/${KP_PACKAGE_NAME}"

test "$(dpkg-deb -f "${KP_OUTPUT_DIR}/${KP_PACKAGE_NAME}" Package)" = 'com.stealth.kexproof'
test "$(dpkg-deb -f "${KP_OUTPUT_DIR}/${KP_PACKAGE_NAME}" Version)" = "${KP_PACKAGE_VERSION}"
test "$(dpkg-deb -f "${KP_OUTPUT_DIR}/${KP_PACKAGE_NAME}" Architecture)" = 'iphoneos-arm64'

# Unsigned IPA for sideloading (AltStore/SideStore): Payload/KexProof.app zipped.
# The app inside carries the same ldid pseudo-signature as the deb; the
# sideloader re-signs it with the user's development certificate.
command -v zip >/dev/null
mkdir -p "${KP_IPA_DIR}/Payload"
cp -R "${KP_BUILD_DIR}/.theos/_/var/jb/Applications/KexProof.app" \
    "${KP_IPA_DIR}/Payload/"
(cd "${KP_IPA_DIR}" && zip -qr "${KP_OUTPUT_DIR}/${KP_IPA_NAME}" Payload)

test -f "${KP_OUTPUT_DIR}/${KP_IPA_NAME}"

sha256sum "${KP_OUTPUT_DIR}/${KP_PACKAGE_NAME}" "${KP_OUTPUT_DIR}/${KP_IPA_NAME}"
