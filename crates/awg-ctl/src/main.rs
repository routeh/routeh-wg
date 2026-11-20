//! `awg-ctl <socket>`: started by procd in ujail with the path of the
//! plugin's channel, and nothing else.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    routeh_plugin_sdk::run(awg_ctl::Awg::new(awg_ctl::kernel::Netlink::default()))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("awg-ctl runs on Linux only");
    std::process::ExitCode::FAILURE
}
