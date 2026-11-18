# routeh-wg

The AmneziaWG plugin for the routeh router: the AWG 3.1 kernel module
built for OpenWrt, and the Rust service that keeps the router's tunnels
with it.

```
crates/awg-netlink   netlink binding for the amneziawg module (and WireGuard)
crates/awg-ctl       the plugin's service: desired in, devices converged, state out
kmod/                the module: pinned source, the SDK's host image, its build
plugin/manifest.toml the plugin's manifest and version
targets.toml         the OpenWrt targets built
xtask/               cargo xtask: build, bundle, verify, the QEMU test
docs/                NETLINK.md, AWG-CTL.md, BUILD.md
```

```sh
cargo test --workspace
cargo xtask build        # bundles in target/awg/bundles
cargo xtask qemu-test    # the module and both layers on OpenWrt in QEMU
cargo xtask publish --feed <feed checkout> --key <secret key> target/awg/bundles/*.tar
```

Needs Rust, Docker, and for the QEMU test `qemu-system-aarch64`.
How a build, a version and the feed work: `docs/BUILD.md`.
