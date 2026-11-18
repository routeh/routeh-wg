# The AmneziaWG kernel module as an OpenWrt package, built with the SDK of
# the exact release and target it is for. `cargo xtask kmod` builds the
# module alone with the SDK (kmod/build.sh); this package is
# where the source is pinned, and stays buildable as a package.
#
# The source is amneziawg-linux-kernel-module at a fixed commit, built out
# of tree against the SDK's kernel: the module of AWG 3.1, not the kernel's
# WireGuard with the AWG 1.0 patches of amneziawg-openwrt.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=amneziawg
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git
PKG_SOURCE_DATE:=2026-11-13
PKG_SOURCE_VERSION:=63ed35de3d3f135b17e8eae0b84949e7700303be
PKG_MIRROR_HASH:=skip
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0-only
PKG_LICENSE_FILES:=COPYING
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# What `requires` of plugin/manifest.toml names; `cargo xtask bundle` checks
# the module's own `depends` against it.
define KernelPackage/amneziawg
  SUBMENU:=Network Support
  TITLE:=AmneziaWG (kernel module of AWG 3.1)
  URL:=https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
  DEPENDS:= \
	+kmod-udptunnel4 \
	+kmod-udptunnel6 \
	+kmod-crypto-lib-chacha20poly1305 \
	+kmod-crypto-lib-curve25519
  FILES:=$(PKG_BUILD_DIR)/src/amneziawg.ko
endef

define KernelPackage/amneziawg/description
  The AmneziaWG module, loaded by the router's plugin loader, never by
  the system: no
  AUTOLOAD.
endef

# Not the module's own Makefile: it sets WIREGUARD_VERSION=1.0.0, which
# would hide the version of src/version.h from /sys/module/amneziawg/version.
define Build/Compile
	+$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)/src" modules
endef

$(eval $(call KernelPackage,amneziawg))
