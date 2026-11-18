//! `cargo xtask <command>`: every step of a build, the same on a laptop and
//! in CI (docs/BUILD.md). Everything it makes is under `target/awg/`.

mod bundle;
mod cmd;
mod docker;
mod feed;
mod keys;
mod openwrt;
mod qemu;

use std::path::Path;

use cmd::{fail, Args};

const USAGE: &str = "\
cargo xtask <command>

  build     [--openwrt R] [--targets T]   everything: awg-ctl, amneziawg.ko, bundles, checked
  qemu-test [--openwrt R]                 the module and both layers on OpenWrt in QEMU
  publish   --feed DIR --key SECRET [BUNDLE...] [--expires-days 90]
                                          sign bundles into a feed's checkout, sign its index

  version                                 the plugin's version
  targets   [--openwrt R] [--targets T]   targets of a release, as JSON (a CI matrix)
  kmod      --openwrt R --target T        amneziawg.ko with the release's SDK
  ctl       --rust TRIPLE                 awg-ctl for a Rust target
  bundle    --openwrt R --target T        the bundle of a target, unsigned (kmod and ctl first)
  verify    FILE... [--trust PUBLIC]      check bundles as the router reads them
  missing   --feed DIR [--openwrt R]      targets the feed has no build of this version for
  keygen    SECRET PUBLIC [COMMENT]       a key pair in the router's form

  R  a release (25.12.6) or `stable` (the default)
  T  `all` (the default: targets.toml) or a comma list (mediatek/filogic,armsr/armv8)
  --native  the SDK and cargo on this host, not in Docker (x86_64 Linux: CI)
";

fn main() {
    let args = Args::parse();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::env::set_current_dir(root).unwrap_or_else(|e| fail(format!("{}: {e}", root.display())));
    let native = args.has("native");
    let r = match args.command.as_deref() {
        Some("build") => build(&args, native),
        Some("qemu-test") => release(&args).and_then(|r| qemu::test(&r, native)),
        Some("version") => {
            println!("{}", bundle::plugin_version());
            Ok(())
        }
        Some("targets") => release(&args).and_then(|r| {
            let list = openwrt::resolve(&r, args.get("targets").unwrap_or("all"))?;
            println!("{}", serde_json::to_string(&list).unwrap());
            Ok(())
        }),
        Some("kmod") => release(&args).and_then(|r| openwrt::build_kmod(&r, args.need("target")?, native)),
        Some("ctl") => args.need("rust").and_then(|rust| docker::build_ctl(rust, native)),
        Some("bundle") => release(&args).and_then(|r| {
            let t = openwrt::resolve(&r, args.need("target")?)?.remove(0);
            println!("{}", bundle::make(&t)?.display());
            Ok(())
        }),
        Some("publish") => (|| {
            let key = keys::Secret::read(args.need("key")?)?;
            let days = args.get("expires-days").map_or(Ok(90), |d| d.parse().map_err(|_| "--expires-days: a number"))?;
            feed::publish(Path::new(args.need("feed")?), &key, &args.rest, days)
        })(),
        Some("missing") => release(&args).and_then(|r| {
            println!("{}", feed::missing(Path::new(args.need("feed")?), &r)?);
            Ok(())
        }),
        Some("verify") if !args.rest.is_empty() => (|| {
            let trust = args.get("trust").map(keys::read_public).transpose()?;
            args.rest.iter().try_for_each(|f| {
                if let Some(t) = trust {
                    if bundle::check(Path::new(f))?.1 != Some(t) {
                        return Err(format!("{f}: not signed by {}", keys::b64(&t)));
                    }
                }
                println!("{f}: {}", bundle::verify(Path::new(f))?);
                Ok(())
            })
        })(),
        Some("keygen") if (2..=3).contains(&args.rest.len()) => (|| {
            let k = keys::Secret::generate()?;
            let write = |path: &str, text: String, mode: u32| -> Result<(), String> {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path)
                    .map_err(|e| format!("{path}: {e}"))?;
                f.write_all(text.as_bytes()).map_err(|e| format!("{path}: {e}"))
            };
            write(&args.rest[0], k.line(), 0o600)?;
            write(&args.rest[1], k.public_line(args.rest.get(2).map_or("", String::as_str)), 0o644)
        })(),
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        fail(e);
    }
}

fn release(args: &Args) -> Result<String, String> {
    openwrt::release(args.get("openwrt").unwrap_or("stable"))
}

fn build(args: &Args, native: bool) -> Result<(), String> {
    let list = openwrt::resolve(&release(args)?, args.get("targets").unwrap_or("all"))?;
    let mut rusts: Vec<&str> = list.iter().map(|t| t.rust.as_str()).collect();
    rusts.sort();
    rusts.dedup();
    for rust in rusts {
        eprintln!("== awg-ctl {rust}");
        docker::build_ctl(rust, native)?;
    }
    for t in &list {
        eprintln!("== {} on {}: amneziawg.ko", t.target, t.openwrt);
        openwrt::build_kmod(&t.openwrt, &t.target, native)?;
        let out = bundle::make(t)?;
        eprintln!("== {}: {}", out.display(), bundle::verify(&out)?);
    }
    Ok(())
}
