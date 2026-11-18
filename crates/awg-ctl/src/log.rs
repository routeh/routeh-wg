//! The system log: program `awg`, a tunnel's lines as `awg/<key>`. To
//! stderr where there is no `/dev/log`.

use std::os::unix::net::UnixDatagram;

pub struct Log {
    sock: Option<UnixDatagram>,
}

const FACILITY_DAEMON: u8 = 3;
pub const ERR: u8 = 3;
pub const INFO: u8 = 6;

impl Log {
    pub fn open() -> Self {
        let sock = UnixDatagram::unbound().ok().filter(|s| s.connect("/dev/log").is_ok());
        Self { sock }
    }

    pub fn write(&self, level: u8, key: Option<&str>, text: &str) {
        let tag = match key {
            Some(k) => format!("awg/{k}"),
            None => "awg".to_owned(),
        };
        let pid = std::process::id();
        match &self.sock {
            Some(s) => {
                let line = format!("<{}>{tag}[{pid}]: {text}", FACILITY_DAEMON * 8 + level);
                let _ = s.send(line.as_bytes());
            }
            None => eprintln!("{tag}: {text}"),
        }
    }
}
