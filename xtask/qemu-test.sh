#!/bin/sh
# xtask/qemu-test.sh <release> <kmod dir> <bin dir> <cache dir>
# Run by `cargo xtask qemu-test`, which builds what it takes.
#
# Boots OpenWrt <release> armsr/armv8 in QEMU (HVF on Apple Silicon, KVM on
# an arm64 Linux host, emulated elsewhere; the disk a snapshot, nothing
# kept), installs the module's dependencies, loads <kmod dir>/amneziawg.ko
# and runs <bin dir>/live (awg-netlink on the module) and <bin dir>/e2e (a
# handshake made by awg-ctl's engine), each required to find the module.
#
# Needs qemu-system-aarch64 and its aarch64 UEFI firmware (QEMU_EFI names
# it when it is not where Homebrew or Debian put it).
set -eu
release=$1 kmod=$2 bin=$3 cache=$4
port=${QEMU_SSH_PORT:-2291}   # not 2222, which other test VMs often take
mkdir -p "$cache"

base="https://downloads.openwrt.org/releases/$release/targets/armsr/armv8"
img_gz="openwrt-$release-armsr-armv8-generic-ext4-combined-efi.img.gz"
img="$cache/${img_gz%.gz}"
if [ ! -f "$img" ]; then
  [ -f "$cache/$img_gz" ] || curl -fsS -o "$cache/$img_gz" "$base/$img_gz"
  want=$(curl -fsS "$base/sha256sums" | awk -v n="*$img_gz" '$2 == n { print $1 }')
  got=$(shasum -a 256 "$cache/$img_gz" | cut -d' ' -f1)
  [ "$want" = "$got" ] || { echo "image checksum mismatch" >&2; exit 1; }
  gunzip -c "$cache/$img_gz" > "$img" 2>/dev/null || true # "trailing garbage" is its signature
fi

echo "== boot OpenWrt $release armsr/armv8"
if [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ]; then
  accel="-accel hvf -cpu host"
elif [ "$(uname -m)" = "aarch64" ] && [ -w /dev/kvm ]; then
  accel="-accel kvm -cpu host"
else
  accel="-accel tcg -cpu cortex-a57"
fi
efi=${QEMU_EFI:-}
for f in "$(dirname "$(command -v qemu-system-aarch64)")/../share/qemu/edk2-aarch64-code.fd" \
         /usr/share/qemu/edk2-aarch64-code.fd /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
  [ -n "$efi" ] || { [ -f "$f" ] && efi=$f; }
done
[ -n "$efi" ] || { echo "no aarch64 UEFI firmware: set QEMU_EFI" >&2; exit 1; }
pidfile="$cache/qemu.pid"
[ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
# shellcheck disable=SC2086
qemu-system-aarch64 -M virt $accel -m 512 -smp 2 -bios "$efi" \
  -drive file="$img",format=raw,if=virtio,snapshot=on \
  -netdev user,id=lan,net=192.168.1.0/24,host=192.168.1.2,dns=192.168.1.3,dhcpstart=192.168.1.100,hostfwd=tcp:127.0.0.1:$port-192.168.1.1:22 \
  -device virtio-net-pci,netdev=lan,romfile= \
  -display none -serial file:"$cache/serial.log" -daemonize -pidfile "$pidfile"
trap 'kill "$(cat "$pidfile")" 2>/dev/null || true' EXIT

# A fresh OpenWrt has no root password: ssh is given an empty one.
askpass="$cache/askpass"
printf '#!/bin/sh\necho\n' > "$askpass"; chmod +x "$askpass"
vm() {
  SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=: \
    ssh -p "$port" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=3 root@127.0.0.1 "$@"
}
for _ in $(seq 1 120); do vm true 2>/dev/null && break; sleep 2; done
vm true

echo "== the module's dependencies"
# From a local copy of the release's kmods repository, its signed index
# and the packages: the guest needs no network. What apk names as missing
# is fetched too, until nothing is.
kver=$(sed -n 's/.*"kernel_package": "\([^"]*\)".*/\1/p' "$kmod/meta.json")
kdir=$(echo "$kver" | sed 's/^\([^~]*\)~\([^-]*\)-r\(.*\)$/\1-\3-\2/')   # 6.12.112-1-<hash>
kurl="$base/kmods/$kdir"
apks="$cache/apk-$kdir"
mkdir -p "$apks"
pkgs="kmod-udptunnel4 kmod-udptunnel6 kmod-crypto-lib-chacha20poly1305 kmod-crypto-lib-curve25519"
listing=$(curl -fsS "$kurl/")
[ -f "$apks/packages.adb" ] || curl -fsS -o "$apks/packages.adb" "$kurl/packages.adb"
vm 'rm -rf /tmp/apk && mkdir -p /tmp/apk' && vm "cat > /tmp/apk/packages.adb" < "$apks/packages.adb"
need=$pkgs
for _ in 1 2 3 4 5 6; do
  for p in $need; do
    f=$(echo "$listing" | grep -oE "href=\"$p-[0-9][^\"]*\.apk\"" | head -1 | sed 's/href=//; s/"//g')
    [ -n "$f" ] || { echo "no $p in $kurl" >&2; exit 1; }
    [ -f "$apks/$f" ] || curl -fsS -o "$apks/$f" "$kurl/$f"
    vm "cat > /tmp/apk/$f" < "$apks/$f"
  done
  out=$(vm "apk add --no-network --repositories-file /dev/null -X /tmp/apk/packages.adb $pkgs 2>&1" || true)
  need=$(echo "$out" | sed -n 's/^ERROR: \(.*\)-[0-9][^ ]*: package mentioned in index not found.*/\1/p')
  [ -n "$need" ] || break
done
echo "$out" | tail -1

echo "== load the module"
for f in "$kmod/amneziawg.ko" "$bin/live" "$bin/e2e" "$bin/awg-ctl"; do
  vm "cat > /tmp/$(basename "$f") && chmod +x /tmp/$(basename "$f")" < "$f"
done
# As the router does: the module's own depends first (insmod loads none).
deps=$(sed -n 's/.*"depends": "\([^"]*\)".*/\1/p' "$kmod/meta.json" | tr , ' ')
vm "for d in $deps; do modprobe \$d || exit 1; done; insmod /tmp/amneziawg.ko && dmesg | grep -i amneziawg | tail -1"

echo "== awg-netlink on the module"
vm 'AWG_LIVE=1 AWG_REQUIRE=amneziawg /tmp/live --test-threads=1'
echo "== a handshake by awg-ctl's engine"
vm 'AWG_LIVE=1 AWG_REQUIRE=amneziawg /tmp/e2e --test-threads=1'
vm 'poweroff' 2>/dev/null || true
