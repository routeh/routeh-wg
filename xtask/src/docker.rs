//! The only two places anything runs in Docker, each with a `--native`
//! twin for CI:
//!
//! - the OpenWrt SDK, in the image of `kmod/Dockerfile` (linux/amd64: the
//!   SDK's tools are x86_64), with SDKs kept in the volume `routeh-wg-sdk`;
//! - cargo for a musl target, in `rust-musl-cross` (its cross toolchain),
//!   with the registry in the volume `routeh-wg-cargo`.

use std::process::Command;

use crate::cmd::{mkdir, pwd, run, stdout, OUT};

/// Builds for a musl target go here, apart from the host's builds.
pub const CROSS_TARGET_DIR: &str = "target/cross";

fn cross_image(rust: &str) -> Result<&'static str, String> {
    Ok(match rust {
        "aarch64-unknown-linux-musl" => "ghcr.io/rust-cross/rust-musl-cross:aarch64-musl",
        "armv7-unknown-linux-musleabihf" => "ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf",
        "x86_64-unknown-linux-musl" => "ghcr.io/rust-cross/rust-musl-cross:x86_64-musl",
        _ => return Err(format!("no musl toolchain for {rust}")),
    })
}

/// `cargo <args> --target <rust>`, its standard output returned. Paths in
/// it are of this checkout either way (the container's /src is mapped back).
pub fn cargo(rust: &str, args: &[&str], env: &[(&str, &str)], native: bool) -> Result<String, String> {
    let mut all: Vec<&str> = args.to_vec();
    all.extend(["--target", rust, "--target-dir", CROSS_TARGET_DIR]);
    let out = if native {
        let mut c = Command::new("cargo");
        c.args(&all).envs(env.iter().copied());
        stdout(&mut c)?
    } else {
        let mut c = Command::new("docker");
        c.args(["run", "--rm", "-v", &format!("{}:/src", pwd()), "-w", "/src"])
            .args(["-v", "routeh-wg-cargo:/root/.cargo/registry"]);
        for (k, v) in env {
            c.args(["-e", &format!("{k}={v}")]);
        }
        c.arg(cross_image(rust)?).arg("cargo").args(&all);
        stdout(&mut c)?.replace("\"/src/", &format!("\"{}/", pwd()))
    };
    Ok(out)
}

/// `target/awg/ctl/<rust>/awg-ctl`: static, the plugin's version in its hello.
pub fn build_ctl(rust: &str, native: bool) -> Result<(), String> {
    let version = crate::bundle::plugin_version();
    cargo(rust, &["build", "-q", "--release", "-p", "awg-ctl"], &[("AWG_PLUGIN_VERSION", &version)], native)?;
    let dir = format!("{OUT}/ctl/{rust}");
    mkdir(&dir)?;
    std::fs::copy(format!("{CROSS_TARGET_DIR}/{rust}/release/awg-ctl"), format!("{dir}/awg-ctl"))
        .map_err(|e| format!("awg-ctl for {rust}: {e}"))?;
    Ok(())
}

/// kmod/build.sh with RELEASE, TARGET and an output directory.
pub fn sdk(release: &str, target: &str, out: &str, native: bool) -> Result<(), String> {
    if native {
        let sdk = std::env::var("SDK_DIR").unwrap_or_else(|_| format!("{}/{OUT}/sdk", pwd()));
        return run(Command::new("sh")
            .arg("kmod/build.sh")
            .env("RELEASE", release)
            .env("TARGET", target)
            .env("KMOD_DIR", format!("{}/kmod", pwd()))
            .env("SDK_DIR", sdk)
            .env("OUT_DIR", format!("{}/{out}", pwd())));
    }
    let dockerfile = std::fs::read("kmod/Dockerfile").map_err(|e| e.to_string())?;
    let image = format!("routeh-wg-sdk:{}", &crate::bundle::sha256_hex(&dockerfile)[..12]);
    let have = Command::new("docker").args(["image", "inspect", &image]).output().is_ok_and(|o| o.status.success());
    if !have {
        eprintln!("== the SDK's image {image}");
        stdout(Command::new("docker").args(["build", "-q", "--platform", "linux/amd64", "-t", &image, "kmod"]))?;
    }
    run(Command::new("docker").args([
        "run", "--rm", "--platform", "linux/amd64",
        "-v", &format!("{}/kmod:/kmod:ro", pwd()),
        "-v", &format!("{}/{out}:/out", pwd()),
        "-v", "routeh-wg-sdk:/sdk",
        "-e", &format!("RELEASE={release}"),
        "-e", &format!("TARGET={target}"),
        &image, "sh", "-eu", "/kmod/build.sh",
    ]))
}
