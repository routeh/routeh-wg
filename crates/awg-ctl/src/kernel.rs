//! The module through `awg-netlink`. Linux only.

use awg_netlink::{Client, Device, DeviceUpdate, Error, Flavor};

use crate::engine::Kernel;

/// The client is made when first needed and dropped after a failure, so a
/// module loaded later, or loaded again (with a new family id), is found.
#[derive(Default)]
pub struct Netlink {
    client: Option<Client>,
}

impl Netlink {
    fn client(&mut self) -> Result<&mut Client, Error> {
        if self.client.is_none() {
            self.client = Some(Client::new(Flavor::Amnezia)?);
        }
        Ok(self.client.as_mut().unwrap())
    }

    fn call<T>(&mut self, f: impl FnOnce(&mut Client) -> Result<T, Error>) -> Result<T, Error> {
        let r = f(self.client()?);
        if matches!(r, Err(Error::Io(_)) | Err(Error::NoFamily(_)) | Err(Error::Malformed(_))) {
            self.client = None;
        }
        r
    }
}

impl Kernel for Netlink {
    fn ready(&mut self) -> Result<(), String> {
        match self.client() {
            Ok(_) => Ok(()),
            Err(Error::NoFamily(_)) => Err("the amneziawg module is not loaded".into()),
            Err(e) => Err(format!("netlink: {e}")),
        }
    }
    fn links(&mut self) -> Result<Vec<String>, Error> {
        self.call(|c| c.links()).map(|l| l.into_iter().map(|l| l.name).collect())
    }
    fn create(&mut self, name: &str) -> Result<(), Error> {
        self.call(|c| c.create_link(name))
    }
    fn delete(&mut self, name: &str) -> Result<(), Error> {
        self.call(|c| c.delete_link(name))
    }
    fn get(&mut self, name: &str) -> Result<Device, Error> {
        self.call(|c| c.get_device(name))
    }
    fn set(&mut self, u: &DeviceUpdate) -> Result<(), Error> {
        self.call(|c| c.set_device(u))
    }
    /// OpenWrt strips `MODULE_VERSION` from modules (`CONFIG_MODULE_STRIPPED`),
    /// so `/sys/module/amneziawg/version` is there only on other systems.
    /// In a bundle the version is in `build.json` beside `bin/`.
    fn module_version(&mut self) -> Option<String> {
        if let Ok(v) = std::fs::read_to_string("/sys/module/amneziawg/version") {
            return Some(v.trim().to_owned());
        }
        std::fs::metadata("/sys/module/amneziawg").ok()?;
        let exe = std::env::current_exe().ok()?;
        let build = exe.parent()?.parent()?.join("build.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(build).ok()?).ok()?;
        v.get("module_version")?.as_str().map(str::to_owned)
    }
}
