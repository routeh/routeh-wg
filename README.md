# routeh-wg

The AmneziaWG plugin for the routeh router: the AWG 3.1 kernel module
built for OpenWrt, and the service that keeps the router's tunnels with
it. A plugin of routeh-plugin: its service is written on
`routeh-plugin-sdk`, built and released by `routeh-plugin-build`.

```
crates/awg-netlink   netlink binding for the amneziawg module (and WireGuard)
crates/awg-ctl       the plugin's service: desired in, devices converged, state out
kmod/amneziawg/      the module: its pinned source, patches/
plugin/manifest.toml the plugin's manifest and version
build.toml           what is built: targets, the service, the module, QEMU tests
xtask/               cargo xtask: routeh-plugin-build's commands
docs/                NETLINK.md, AWG-CTL.md, BUILD.md
```

```sh
cargo test --workspace
cargo xtask build        # bundles in target/routeh/bundles
cargo xtask qemu-test    # the module and both layers on OpenWrt in QEMU
```

Needs Rust, Docker, and for the QEMU test `qemu-system-aarch64`. The
version, the module and releases: `docs/BUILD.md`.
