# Building and releasing

Every step is a `cargo xtask` command, the same on a laptop and in CI.
Everything it makes and keeps is under `target/awg/`.

```sh
cargo xtask build                       # every target of targets.toml, stable OpenWrt
cargo xtask build --openwrt 25.12.6 --targets mediatek/filogic
cargo xtask qemu-test                   # the module and both layers on OpenWrt in QEMU
cargo xtask                             # every command
```

| Command | Makes |
|---|---|
| `build` | all below for each target, each bundle checked |
| `targets` | the targets of a release: arch, Rust target, kernel, bundle name (JSON, a CI matrix) |
| `kmod` | `kmod/<release>/<target>/amneziawg.ko`, `meta.json` |
| `ctl` | `ctl/<rust>/awg-ctl` |
| `bundle` | `bundles/<name>.tar` (unsigned) and `.json` |
| `publish` | signs bundles into a checkout of the feed and signs its index (The feed) |
| `missing` | the targets of a release the feed has no build of this version for |
| `keygen` | a key pair in the router's form |
| `verify` | checks bundles as the router will before unpacking |
| `qemu-test` | builds what it needs, then `xtask/qemu-test.sh` |

Docker is used in two places only (`xtask/src/docker.rs`): the OpenWrt SDK
in the image of `kmod/Dockerfile` (linux/amd64: the SDK's tools are x86_64),
and cargo for musl targets in `rust-musl-cross`. `--native` runs both on
the host instead: CI on x86_64 Linux. Two volumes keep downloads between
runs: `routeh-wg-sdk`, `routeh-wg-cargo`.

## Targets and the version

`targets.toml` lists the OpenWrt targets. The release is chosen per build
(`--openwrt`, default the current stable); a target's architecture and
kernel come from that release's `profiles.json`, the architecture's Rust
target from `[rust]`. A new router is one line.

`version` of `plugin/manifest.toml` is **`<AWG version>-r<revision>`**:

```
3.1.20261113.2-r1
└ AWG 3.1.20261113-02  └ ours: awg-ctl, the manifest, patches
```

- The AWG part is the module's `version.h` at the commit pinned in
  `kmod/amneziawg/Makefile`, its numbers joined by dots; `bundle` refuses a
  version that is not of the module it carries. A new AWG commit: its
  version and `-r1`. A change of ours: `-r<n+1>`. Compared as apk compares.
- **The kernel is not in the version.** A new OpenWrt release is another
  bundle of the same version; the bundle's name carries the kernel:
  `awg-3.1.20261113.2-r1-aarch64_generic-6.12.112-1-67e205f2….tar`.

## The module

`kmod/build.sh` builds `amneziawg.ko` with the OpenWrt SDK of the release
and target:

- the source is amneziawg-linux-kernel-module at the commit of
  `kmod/amneziawg/Makefile` (a valid OpenWrt package, and the one place the
  source is pinned), with `kmod/patches/*.patch` applied;
- only the module: `make -C <SDK kernel> M=src modules` with the SDK's
  toolchain and OpenWrt's kernel make flags (`KERNEL_MAKE`). `make
  package/...` would build and pack every kmod of `package/kernel/linux`;
- the kernel package version (`6.12.112~<hash>-r1`, the SDK's
  `LINUX_VERSION~LINUX_VERMAGIC-rLINUX_RELEASE`) must be the one the
  release's `profiles.json` states;
- reproducible: a fixed build path, so the same source and SDK give the
  same `.ko`. In Docker and `--native` the SDK's path differs, and so may
  the bytes: CI builds one way.

About 20 s once the SDK is downloaded.

`meta.json`: release, target, kernel package, vermagic, the module's build
id and version, `depends`, the upstream commit, a digest of the patches.

**What OpenWrt's kernel takes away.** `CONFIG_MODULE_STRIPPED`: no
`version`, `description` or `srcversion` in a module, so neither
`/sys/module/amneziawg/version` nor `srcversion` exist on a router. No
`notes/` either: the build id is in the file, not readable from the loaded
module. Module parameters survive: a read-only parameter with a stamp of
the build would tell the router whether the loaded module is the bundle's.

**Its dependencies.** `depends`: `libcurve25519-generic`, `udp_tunnel`,
`ip6_udp_tunnel`, `libchacha20poly1305`, from `kmod-crypto-lib-curve25519`,
`kmod-udptunnel4`, `kmod-udptunnel6`, `kmod-crypto-lib-chacha20poly1305`
(which bring `kmod-crypto-lib-chacha20`, `-poly1305` and `kmod-crypto-kpp`).
`insmod` loads none of them: they are loaded first, by name, as the router
loads a plugin's modules in the order of `depends`.

## The bundle

The router's format, and the bytes its own packer makes of the same files
and key:

```
bin/awg-ctl           static; installed 0755 (under bin/)
build.json            plugin, version, release, target, arch, kernel package,
                      vermagic, module build id and version, depends, upstream
manifest.toml         plugin/manifest.toml with [modules] kernel set to the build's
modules/amneziawg.ko
SHA256SUMS            "<sha256>  <path>" of each file above, in the order of paths
SHA256SUMS.sig        "ed25519 <public key> <signature of SHA256SUMS>", by `publish`
```

- A POSIX ustar archive, no compression: regular files in the order of their
  paths, mode 0644 or 0755 under `bin/`, owner 0, time 0, then the list
  and its signature. The same inputs give the same bytes.
- `[modules] kernel` of the manifest is the `kernel` package version the
  module is built for; the router's `install` compares it with its own.
  So each bundle has its own manifest, written by `bundle`;
  `plugin/manifest.toml` has none.
- `bundle` writes it **unsigned**; `publish` signs it with the feed's key
  as it puts it into the feed. Keys and signatures are the router's lines
  (`ed25519-secret …`, `ed25519 …`) with its arithmetic (ring 0.17.14).
- `bundle` checks first: the version is of the module, the module is for the
  release's kernel and has the vermagic it says, both binaries are for the
  architecture, every `depends` of the module is a package
  (`[module_packages]` of targets.toml) in `requires` of the manifest.
- `verify` checks what the router checks when it opens a bundle, but the
  signature's key (`--trust <public key>` checks that too): regular files
  and directories only, safe paths,
  1024 files, 32 MiB a file, 64 MiB in all; `SHA256SUMS` in order and of
  every file; the service's command and each module the manifest loads in
  the bundle; and that build.json and the manifest agree.

Checked against the router's own code (2026-11-19): a feed written by
`publish` is opened as the router opens one (signature, format, serial; an
older serial than the router has seen is refused), resolved for an
aarch64_generic router on 6.12.112, its blob checked by size and digest
and opened as a bundle (signature, digests, the manifest with every type
of `[tunnel.settings]`, the module's modinfo). The signed blob is byte for
byte what the router's own packer makes of the bundle's files and the
same key, and `index.json.sig` what its signer makes of the index.

## The QEMU test

`cargo xtask qemu-test` builds the module for armsr/armv8, awg-ctl and the
test binaries for aarch64, then `xtask/qemu-test.sh` boots that OpenWrt
release in QEMU (HVF on Apple Silicon, KVM on arm64 Linux, emulated
elsewhere; a snapshot disk, SSH on 127.0.0.1:2291), installs the module's
dependencies from a local copy of the release's kmods repository (its signed
`packages.adb` and the packages; the guest needs no network), loads the
module and runs awg-netlink's `tests/live.rs` and awg-ctl's `tests/e2e.rs`
with `AWG_REQUIRE=amneziawg`, so a missing module fails rather than skips.

## CI

| Workflow | When | Does |
|---|---|---|
| `ci.yml` | every push, pull request | clippy `-D warnings`, tests, awg-netlink's live test on the runner's WireGuard |
| `build.yml` | a tag `v<version>`; by hand | the bundles of a version for an OpenWrt release, tested, signed and pushed into the feed |
| `watch.yml` | daily; Mondays; by hand | `build.yml` for the targets the feed lacks a bundle of the latest tag for on the stable release (a new kernel); on Mondays the index signed again |

`build.yml` by hand (Actions → build → Run workflow): `version` (a tag;
empty is the latest, built from that tag's own code and pins), `openwrt` (a
release or `stable`), `targets` (`all` or a list), `publish` (into the
feed; only a tag is published). Its jobs: `plan` (the tag is the
manifest's version; the matrix), `ctl` per Rust target, `bundle` per target
(`kmod --native`, the SDK cached), `qemu` when armsr/armv8 is built,
`publish` once both passed.

- A new version: `version` in `plugin/manifest.toml` (and the commit in
  `kmod/amneziawg/Makefile` for a new AWG), push, tag `v<version>`.
- A new kernel: nothing; `watch.yml` builds and publishes it, or run
  `build.yml`.

## The feed

One feed for every plugin of the router: a router has one feed's
address. It is a repository of its own, served as it is by
GitHub Pages (a domain of one's own in front lets it move later without
touching a router), in the router's format:

```
index.json        {"feed": 1, "serial", "expires", "plugins": {"awg": [{"version", "builds": [
                    {"arch", "kernel", "blob": "sha256:…", "size"}]}]}}
index.json.sig    "ed25519 <public key> <signature of index.json>"
blobs/<sha256>    each signed bundle, by the SHA-256 of its bytes
```

`cargo xtask publish --feed <checkout> --key <secret key> <bundle.tar>...`
signs each bundle, writes it to `blobs/`, adds its build to the index (a
build of the same version, architecture and kernel is replaced), raises
`serial`, sets `expires` (90 days), and signs the index. It refuses a feed
whose index another key signed. With no bundles it only signs the index
again. The same works by hand against a local checkout.

`build.yml`'s `publish` job checks the feed out, runs that, commits and
pushes; one job at a time writes the feed (`concurrency: feed`), and a push
refused because another came first is done again from the new state.

What it needs, once:

1. The feed's repository, with GitHub Pages on its default branch.
2. A key pair: `cargo xtask keygen feed.key feed.pub "awg feed"`. The
   public line goes to each router, among the keys it trusts; the secret
   line goes to
   GitHub, below, and nowhere else.
3. In this repository: the variable `FEED_REPOSITORY` (owner/name), the
   secret `FEED_DEPLOY_KEY` (the private half of a deploy key of the feed's
   repository, with write access), and an environment `feed` with the
   secret `FEED_SIGNING_KEY` (the line of `feed.key`). Protect the
   environment to tags, and add reviewers if each publication is to be
   approved.
