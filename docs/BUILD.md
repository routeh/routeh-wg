# Building and releasing

The build is routeh-plugin's (`routeh-plugin-build`, its `docs/BUILD.md`
and `docs/RELEASE.md`): `cargo xtask` here is its one line. What is this
plugin's is `build.toml`, `plugin/manifest.toml`, the module's source in
`kmod/amneziawg/`, and the rules below.

```sh
cargo xtask build                       # every target of build.toml, stable OpenWrt
cargo xtask build --openwrt 25.12.6 --targets mediatek/filogic
cargo xtask qemu-test                   # the module and both layers on OpenWrt in QEMU
cargo xtask                             # every command
```

## The version

`version` of `plugin/manifest.toml` is **`<AWG version>-r<revision>`**:

```
3.1.20261113.2-r1
└ AWG 3.1.20261113-02  └ ours: awg-ctl, the manifest, patches
```

- The AWG part is the module's `version.h` at the commit pinned in
  `kmod/amneziawg/Makefile`, its numbers joined by dots (`pins_version` in
  `build.toml`): a bundle of another version is refused. A new AWG
  commit: its version and `-r1`. A change of ours: `-r<n+1>`.
- **The kernel is not in the version.** A new OpenWrt release is another
  bundle of the same version; the bundle's name carries the kernel:
  `awg-3.1.20261113.2-r1-aarch64_generic-6.12.112-1-67e205f2….tar`.

## The module

- The source is amneziawg-linux-kernel-module at the commit of
  `kmod/amneziawg/Makefile` (a valid OpenWrt package, and the one place
  the source is pinned), with `kmod/amneziawg/patches/*.patch` applied.
- Built alone with the SDK of the exact release and target, about 20 s
  once the SDK is there.

**What OpenWrt's kernel takes away.** `CONFIG_MODULE_STRIPPED`: no
`version`, `description` or `srcversion` in a module, so neither
`/sys/module/amneziawg/version` nor `srcversion` exist on a router; awg-ctl
reads the module's version from the bundle's `build.json`. No `notes/`
either: the build id is in the file, not readable from the loaded module.

**Its dependencies.** `depends`: `libcurve25519-generic`, `udp_tunnel`,
`ip6_udp_tunnel`, `libchacha20poly1305`, from `kmod-crypto-lib-curve25519`,
`kmod-udptunnel4`, `kmod-udptunnel6`, `kmod-crypto-lib-chacha20poly1305`
(the manifest's `requires`; they bring `kmod-crypto-lib-chacha20`,
`-poly1305` and `kmod-crypto-kpp`). The router loads them first.

## The QEMU test

`cargo xtask qemu-test` boots armsr/armv8 of the release, installs the
manifest's `requires`, loads the module and runs awg-netlink's
`tests/live.rs` and awg-ctl's `tests/e2e.rs` in the guest with
`AWG_REQUIRE=amneziawg`, so a missing module fails rather than skips.

## CI

| Workflow | When | Does |
|---|---|---|
| `ci.yml` | every push, pull request | clippy `-D warnings`, tests, awg-netlink's live test on the runner's WireGuard |
| `build.yml` | a tag `v<version>`; by hand; daily | routeh-plugin's `plugin.yml`: the bundles built, tested in QEMU, proposed to the feed; daily only the targets the feed lacks |

- A new version: `version` in `plugin/manifest.toml` (and the commit in
  `kmod/amneziawg/Makefile` for a new AWG), push, tag `v<version>`.
- A new kernel: nothing; the daily run builds and proposes it.

`build.yml` needs the variables `FEED_REPOSITORY` and `FEED_URL` and the
secret `FEED_DEPLOY_KEY`, of the repository or the organisation (not of an
environment: a called workflow is given only those).
