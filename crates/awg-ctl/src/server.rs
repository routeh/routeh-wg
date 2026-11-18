//! The channel's socket: connections, lines, the tick.
//!
//! One thread accepts, one reads each connection, and the main loop owns
//! the engine: every `desired` is converged before the next line is taken,
//! and `state` is sent to every connection when it differs from the last
//! one sent.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::engine::{Engine, Kernel};
use crate::log::{Log, ERR, INFO};
use crate::proto::{self, Hello, Incoming, MAX_LINE};

/// How often the devices are read (and repaired).
pub const TICK: Duration = Duration::from_secs(5);

pub static STOP: AtomicBool = AtomicBool::new(false);

enum Event {
    Connected(u64, UnixStream),
    Line(String),
    Gone(u64),
}

pub fn hello() -> Hello {
    // The plugin's version, set by `cargo xtask ctl`; the crate's otherwise.
    let version = match option_env!("AWG_PLUGIN_VERSION") {
        Some(v) => v,
        None => env!("CARGO_PKG_VERSION"),
    };
    Hello { protocol: proto::PROTOCOL, plugin: "awg", version }
}

pub fn run<K: Kernel>(path: &Path, mut engine: Engine<K>, log: &Log) -> std::io::Result<()> {
    // Bound under another name and renamed into place once it listens, so
    // the name answers from the moment it appears (the router watches the
    // directory for it).
    let staging = PathBuf::from(format!("{}.new", path.display()));
    let _ = std::fs::remove_file(&staging);
    let listener = UnixListener::bind(&staging)?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&staging, path)?;
    let (tx, rx) = mpsc::channel();
    {
        let tx = tx.clone();
        std::thread::spawn(move || accept(listener, tx));
    }
    log.write(INFO, None, &format!("listening on {}", path.display()));

    let mut conns: BTreeMap<u64, UnixStream> = BTreeMap::new();
    let mut last_sent = String::new();
    let mut next_tick = Instant::now() + TICK;

    loop {
        if STOP.load(Ordering::Relaxed) {
            engine.shutdown();
            flush(&mut engine, log);
            let _ = std::fs::remove_file(path);
            log.write(INFO, None, "stopped");
            return Ok(());
        }
        let wait = next_tick.saturating_duration_since(Instant::now()).min(Duration::from_secs(1));
        match rx.recv_timeout(wait) {
            Ok(Event::Connected(id, mut w)) => {
                let state = proto::line("state", &engine.state(SystemTime::now()));
                let ok = w.write_all(proto::line("hello", &hello()).as_bytes()).is_ok()
                    && w.write_all(state.as_bytes()).is_ok();
                if ok {
                    conns.insert(id, w);
                }
            }
            Ok(Event::Line(line)) => match serde_json::from_str::<Incoming>(&line) {
                Ok(Incoming::Desired(d)) => {
                    engine.set_desired(d);
                    engine.converge();
                    flush(&mut engine, log);
                    broadcast(&mut engine, &mut conns, &mut last_sent, log);
                }
                Err(e) => log.write(ERR, None, &format!("a line from the router not read: {e}")),
            },
            Ok(Event::Gone(id)) => {
                conns.remove(&id);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if Instant::now() >= next_tick {
            next_tick = Instant::now() + TICK;
            engine.converge();
            flush(&mut engine, log);
            broadcast(&mut engine, &mut conns, &mut last_sent, log);
        }
    }
}

fn flush<K: Kernel>(engine: &mut Engine<K>, log: &Log) {
    for (key, text) in engine.log.drain(..) {
        log.write(INFO, key.as_deref(), &text);
    }
}

fn broadcast<K: Kernel>(engine: &mut Engine<K>, conns: &mut BTreeMap<u64, UnixStream>, last: &mut String, log: &Log) {
    let line = proto::line("state", &engine.state(SystemTime::now()));
    if line == *last {
        return;
    }
    // The router ends a connection on a longer line of ours: none is sent,
    // and the apply fails for want of a state.
    if line.len() > MAX_LINE {
        if *last != line {
            log.write(ERR, None, &format!("state is {} bytes, over the 64 KiB a line may be; not sent", line.len()));
            *last = line;
        }
        return;
    }
    conns.retain(|_, w| w.write_all(line.as_bytes()).is_ok());
    *last = line;
}

fn accept(listener: UnixListener, tx: mpsc::Sender<Event>) {
    let mut id = 0u64;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        id += 1;
        let Ok(writer) = stream.try_clone() else { continue };
        if tx.send(Event::Connected(id, writer)).is_err() {
            return;
        }
        let tx = tx.clone();
        std::thread::spawn(move || read_lines(id, stream, tx));
    }
}

/// Lines from the router. `desired` has no limit of its own (the router
/// bounds the document it is made from) and is read whole.
fn read_lines(id: u64, stream: UnixStream, tx: mpsc::Sender<Event>) {
    let mut r = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match r.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) if buf.last() != Some(&b'\n') => break, // cut off
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf[..buf.len() - 1]).into_owned();
                if !line.trim().is_empty() && tx.send(Event::Line(line)).is_err() {
                    return;
                }
            }
        }
    }
    let _ = tx.send(Event::Gone(id));
}
