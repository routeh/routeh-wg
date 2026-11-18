//! `awg-ctl <socket>`: started by procd in ujail with the path of the
//! plugin's channel, and nothing else.

use std::path::PathBuf;

use awg_ctl::log::{Log, ERR};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        eprintln!("usage: awg-ctl <socket>");
        std::process::exit(2);
    };
    let log = Log::open();
    if let Err(e) = start(PathBuf::from(path), &log) {
        log.write(ERR, None, &e.to_string());
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn start(path: PathBuf, log: &Log) -> std::io::Result<()> {
    extern "C" fn on_signal(_: libc::c_int) {
        awg_ctl::server::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let engine = awg_ctl::engine::Engine::new(awg_ctl::kernel::Netlink::default());
    awg_ctl::server::run(&path, engine, log)
}

#[cfg(not(target_os = "linux"))]
fn start(_: PathBuf, _: &Log) -> std::io::Result<()> {
    Err(std::io::Error::other("awg-ctl runs on Linux only"))
}
