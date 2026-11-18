//! Arguments, commands, downloads, and where things go.

use std::process::Command;

/// Everything xtask makes and keeps, inside cargo's own `target/`.
pub const OUT: &str = "target/awg";

pub fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("xtask: {e}");
    std::process::exit(1)
}

pub struct Args {
    pub command: Option<String>,
    flags: Vec<(String, Option<String>)>,
    pub rest: Vec<String>,
}

impl Args {
    pub fn parse() -> Self {
        let mut it = std::env::args().skip(1).peekable();
        let command = it.next();
        let (mut flags, mut rest) = (Vec::new(), Vec::new());
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                let value = match it.peek() {
                    Some(v) if !v.starts_with("--") && name != "native" => it.next(),
                    _ => None,
                };
                flags.push((name.to_owned(), value));
            } else {
                rest.push(a);
            }
        }
        Self { command, flags, rest }
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.flags.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }
    pub fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name).ok_or_else(|| format!("--{name} is needed"))
    }
    pub fn has(&self, name: &str) -> bool {
        self.flags.iter().any(|(n, _)| n == name)
    }
}

pub fn run(cmd: &mut Command) -> Result<(), String> {
    let s = cmd.status().map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if s.success() {
        Ok(())
    } else {
        Err(format!("{:?} failed: {s}", cmd.get_program()))
    }
}

/// Its standard output; its errors go to ours.
pub fn stdout(cmd: &mut Command) -> Result<String, String> {
    let o = cmd
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if !o.status.success() {
        return Err(format!("{:?} failed: {}", cmd.get_program(), o.status));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

pub fn fetch(url: &str) -> Result<String, String> {
    stdout(Command::new("curl").args(["-fsSL", url])).map_err(|e| format!("{url}: {e}"))
}

pub fn pwd() -> String {
    std::env::current_dir().unwrap().display().to_string()
}

pub fn mkdir(p: &str) -> Result<(), String> {
    std::fs::create_dir_all(p).map_err(|e| format!("{p}: {e}"))
}
