//! Optional node-local sandbox admission for a dedicated, enrolled worker.
//!
//! The administrator provisions the directory and the initial register before
//! starting containerd. Every shim process, including binary Delete, takes the
//! same lock. The lock file is never replaced.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::libc::{geteuid, O_NOFOLLOW, O_NONBLOCK};
use serde::{Deserialize, Serialize};

pub(crate) const DIRECTORY_ENV: &str = "SMOLVM_SANDBOX_ATTEMPT_BUDGET_DIR";
const REGISTER: &str = "attempts.json";
const NEXT_REGISTER: &str = ".attempts.json.next";
const MAX_ATTEMPTS: usize = 2048;
const MAX_REGISTER_BYTES: u64 = 256 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Register {
    version: u32,
    limit: usize,
    admitted: Vec<String>,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pending: Option<String>,
}

pub(crate) struct AttemptBudget {
    directory: PathBuf,
    _lock: File,
    register: Register,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attempt {
    Unknown,
    Pending,
    Retired,
}

impl AttemptBudget {
    pub(crate) fn configured() -> Result<Option<Self>, String> {
        std::env::var_os(DIRECTORY_ENV)
            .map(|directory| {
                Self::open(Path::new(&directory))
                    .map_err(|error| format!("sandbox attempt register unavailable: {error}"))
            })
            .transpose()
    }

    fn open(directory: &Path) -> io::Result<Self> {
        let metadata = directory.symlink_metadata()?;
        // SAFETY: geteuid takes no arguments and has no caller preconditions.
        let owner = unsafe { geteuid() };
        if !directory.is_absolute()
            || directory.canonicalize()? != directory
            || !metadata.is_dir()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "expected a private, owned register directory",
            ));
        }
        let lock = open_private(&directory.join("lock"), owner)?;
        lock.lock()?;

        let mut bytes = Vec::new();
        open_private(&directory.join(REGISTER), owner)?
            .take(MAX_REGISTER_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_REGISTER_BYTES {
            return Err(io::Error::other("attempt register exceeds its size limit"));
        }
        let register: Register = serde_json::from_slice(&bytes)?;
        let unique = register.admitted.iter().collect::<BTreeSet<_>>();
        if register.version != 1
            || !(1..=MAX_ATTEMPTS).contains(&register.limit)
            || register.admitted.len() > register.limit
            || unique.len() != register.admitted.len()
            || !register.admitted.iter().all(|id| valid_id(id))
            || register
                .pending
                .as_ref()
                .is_some_and(|pending| register.admitted.last() != Some(pending))
        {
            return Err(io::Error::other("invalid sandbox attempt register"));
        }
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
            register,
        })
    }

    pub(crate) fn attempt(&self, id: &str) -> Result<Attempt, String> {
        if !valid_id(id) {
            return Err("sandbox attempt budget requires a 64-digit lowercase hex ID".into());
        }
        if self.register.pending.as_deref() == Some(id) {
            return Ok(Attempt::Pending);
        }
        if self.register.admitted.iter().any(|admitted| admitted == id) {
            return Ok(Attempt::Retired);
        }
        Ok(Attempt::Unknown)
    }

    pub(crate) fn admit(
        &mut self,
        id: &str,
        verify_unused: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        if self.attempt(id)? != Attempt::Unknown {
            return Err("sandbox attempt was already admitted".into());
        }
        if self.register.admitted.len() == self.register.limit {
            return Err("sandbox attempt budget exhausted".into());
        }
        if self.register.pending.is_some() {
            return Err("previous sandbox attempt still requires cleanup".into());
        }
        verify_unused()?;
        self.register.admitted.push(id.into());
        self.register.pending = Some(id.into());
        self.persist()
    }

    /// Call only after the original VM and its share have been removed.
    pub(crate) fn retire(&mut self) -> Result<(), String> {
        self.register.pending = None;
        self.persist()
    }

    fn persist(&self) -> Result<(), String> {
        self.persist_register()
            .map_err(|error| format!("commit sandbox attempt register: {error}"))
    }

    fn persist_register(&self) -> io::Result<()> {
        let next = self.directory.join(NEXT_REGISTER);
        match fs::remove_file(&next) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&next)?;
        serde_json::to_writer(&mut file, &self.register)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(next, self.directory.join(REGISTER))?;
        File::open(&self.directory)?.sync_all()
    }
}

fn open_private(path: &Path, owner: u32) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::other("expected a private, owned register file"));
    }
    Ok(file)
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn fixture(limit: usize) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["lock", REGISTER] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.path().join(name))
                .unwrap();
            if name == REGISTER {
                write!(
                    file,
                    r#"{{"version":1,"limit":{limit},"admitted":[],"pending":null}}"#
                )
                .unwrap();
            }
        }
        directory
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lost_ack_and_cleanup_keep_the_debit() {
        let directory = fixture(1);
        let id = "a".repeat(64);
        AttemptBudget::open(directory.path())
            .unwrap()
            .admit(&id, || Ok(()))
            .unwrap();
        let mut restarted = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Pending);
        assert_eq!(
            restarted.admit(&id, || unreachable!()).unwrap_err(),
            "sandbox attempt was already admitted"
        );
        let refused = "b".repeat(64);
        assert_eq!(
            restarted.admit(&refused, || unreachable!()).unwrap_err(),
            "sandbox attempt budget exhausted"
        );
        assert_eq!(restarted.attempt(&refused).unwrap(), Attempt::Unknown);
        restarted.retire().unwrap();
        drop(restarted);
        let mut restarted = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Retired);
        assert_eq!(
            restarted.admit(&refused, || unreachable!()).unwrap_err(),
            "sandbox attempt budget exhausted"
        );
    }

    #[test]
    fn independent_openers_serialize_admission() {
        let directory = fixture(2);
        let start = Arc::new(Barrier::new(2));
        let writers = ["a", "b"].map(|prefix| {
            let path = directory.path().to_owned();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                AttemptBudget::open(&path)
                    .unwrap()
                    .admit(&prefix.repeat(64), || Ok(()))
            })
        });
        let outcomes = writers.map(|writer| writer.join().unwrap());
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert!(outcomes.iter().any(|outcome| {
            outcome.as_ref().err().map(String::as_str)
                == Some("previous sandbox attempt still requires cleanup")
        }));
    }

    #[test]
    fn missing_or_invalid_register_cannot_reinitialize_admission() {
        let directory = fixture(1);
        let path = directory.path().join(REGISTER);
        fs::write(&path, "{").unwrap();
        assert!(AttemptBudget::open(directory.path()).is_err());
        fs::remove_file(&path).unwrap();
        assert!(AttemptBudget::open(directory.path()).is_err());
        assert!(!path.exists());
    }
}
