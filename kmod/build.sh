# Builds amneziawg.ko with the OpenWrt SDK of RELEASE and TARGET.
# Run by `cargo xtask kmod`: in the image of kmod/Dockerfile (amd64), or
# with --native on an x86_64 Linux host that has its packages (CI).
# Writes amneziawg.ko and meta.json (docs/BUILD.md).
#   KMOD_DIR  this directory           (/kmod)
#   SDK_DIR   SDKs and sources, kept   (/sdk)
#   OUT_DIR   amneziawg.ko, meta.json  (/out)
set -eu
KMOD_DIR=${KMOD_DIR:-/kmod}
SDK_DIR=${SDK_DIR:-/sdk}
OUT_DIR=${OUT_DIR:-/out}
# A fixed path, not mktemp: the path of the sources goes into the module,
# and a module built twice has to be the same file (the same build id).
work=/tmp/awg-kmod
rm -rf "$work" && mkdir -p "$work"

base="https://downloads.openwrt.org/releases/$RELEASE/targets/$TARGET"
sums=$(curl -fsS "$base/sha256sums")
name=$(echo "$sums" | awk '/openwrt-sdk-.*\.tar\.zst$/ { sub(/^\*/, "", $2); print $2 }')
sum=$(echo "$sums" | awk -v n="*$name" '$2 == n { print $1 }')
[ -n "$name" ] && [ -n "$sum" ] || { echo "no SDK at $base" >&2; exit 1; }

mkdir -p "$SDK_DIR" "$OUT_DIR"
cd "$SDK_DIR"
if ! echo "$sum  $name" | sha256sum -c --status 2>/dev/null; then
  echo "downloading $name" >&2
  curl -fsS -o "$name" "$base/$name"
  echo "$sum  $name" | sha256sum -c --status || { echo "SDK checksum mismatch" >&2; exit 1; }
fi
dir="$SDK_DIR/${name%.tar.zst}"
[ -d "$dir" ] || tar --zstd -xf "$name"
cd "$dir"

# The module alone, against the SDK's kernel, with the SDK's toolchain and
# the kernel make flags OpenWrt uses for its own kmods (KERNEL_MAKE of
# include/kernel.mk). Not `make package/...`: that builds and packs every
# kmod of package/kernel/linux the module's package depends on.
commit=$(sed -n 's/^PKG_SOURCE_VERSION:=//p' "$KMOD_DIR/amneziawg/Makefile")
url=$(sed -n 's/^PKG_SOURCE_URL:=//p' "$KMOD_DIR/amneziawg/Makefile")
patches=$(cat "$KMOD_DIR"/patches/*.patch 2>/dev/null | sha256sum | cut -c1-12)
src="$SDK_DIR/src/amneziawg-$commit-$patches"
if [ ! -d "$src" ]; then
  rm -rf "$src.tmp"
  git clone -q "$url" "$src.tmp"
  git -C "$src.tmp" -c advice.detachedHead=false checkout -q "$commit"
  [ "$(git -C "$src.tmp" rev-parse HEAD)" = "$commit" ] || { echo "not at $commit" >&2; exit 1; }
  for p in "$KMOD_DIR"/patches/*.patch; do [ -e "$p" ] && git -C "$src.tmp" apply "$p"; done
  mv "$src.tmp" "$src"
fi
cp -r "$src/src" "$work/mod"

cat > "$work/kmod.mk" <<'MK'
TOPDIR:=$(CURDIR)
export TOPDIR
include rules.mk
include $(INCLUDE_DIR)/kernel.mk
build:
	+$(KERNEL_MAKE) M=$(MOD) modules
val.%:
	@echo $($*)
MK
val() { make --no-print-directory -s -f "$work/kmod.mk" "val.$1"; }
if ! make --no-print-directory -s -f "$work/kmod.mk" build MOD="$work/mod" -j"$(nproc)" > "$work/build.log" 2>&1; then
  tail -60 "$work/build.log" >&2; exit 1
fi
ko="$work/mod/amneziawg.ko"
[ -f "$ko" ] || { echo "no amneziawg.ko built" >&2; exit 1; }
got="$(val LINUX_VERSION)~$(val LINUX_VERMAGIC)-r$(val LINUX_RELEASE)"

# The release's own kernel package must have the same version: else the
# hash is not the firmware's and the module must not be shipped.
want=$(curl -fsS "$base/profiles.json" | python3 -c 'import sys,json; k=json.load(sys.stdin)["linux_kernel"]; print("%s~%s-r%s" % (k["version"], k["vermagic"], k["release"]))')
[ "$want" = "$got" ] || { echo "kernel package version $got is not the release's $want" >&2; exit 1; }

cp "$ko" "$OUT_DIR/amneziawg.ko"
# OpenWrt's kernels strip version, description and srcversion from modules
# (CONFIG_MODULE_STRIPPED); the build id stays in the file.
build_id=$(readelf -n "$OUT_DIR/amneziawg.ko" | sed -n 's/.*Build ID: //p')
[ -n "$build_id" ] || { echo "no build id in the module" >&2; exit 1; }
cat > "$OUT_DIR/meta.json" <<JSON
{
  "release": "$RELEASE",
  "target": "$TARGET",
  "kernel_package": "$got",
  "vermagic": "$(modinfo -F vermagic "$OUT_DIR/amneziawg.ko")",
  "build_id": "$build_id",
  "module_version": "$(sed -n 's/^#define WIREGUARD_VERSION "\(.*\)"$/\1/p' "$src/src/version.h")",
  "depends": "$(modinfo -F depends "$OUT_DIR/amneziawg.ko")",
  "upstream": "$commit",
  "patches": "$patches"
}
JSON
