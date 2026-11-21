//! Optional node-local sandbox admission for a dedicated, enrolled worker.
//!
//! The administrator provisions the directory and the initial register before
//! starting containerd. Every shim process, including binary Delete, takes the
//! same lock. The lock file is never replaced.

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::libc::{geteuid, O_NOFOLLOW, O_NONBLOCK};
use serde::{Deserialize, Serialize};

pub(crate) const DIRECTORY_ENV: &str = "SMOLVM_SANDBOX_ATTEMPT_BUDGET_DIR";
const REGISTER: &str = "attempts.json";
const NEXT_REGISTER: &str = ".attempts.json.next";
const OWNER_LOCK: &str = "sandbox-owner";
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
    #[serde(default)]
    cleanup_requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime: Option<RuntimeStorage>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Storage observed by the writer before allocating anything for the attempt.
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeStorage {
    database: PathBuf,
    database_identity: FileIdentity,
    vm_root: PathBuf,
    vm_root_identity: FileIdentity,
}

impl RuntimeStorage {
    pub(crate) fn read(database: &Path, vm_root: &Path) -> io::Result<Self> {
        let database = database.canonicalize()?;
        let vm_root = vm_root.canonicalize()?;
        let db_metadata = database.metadata()?;
        let vm_metadata = vm_root.metadata()?;
        if !db_metadata.is_file() || !vm_metadata.is_dir() {
            return Err(io::Error::other(
                "expected a VM database file and a VM cache directory",
            ));
        }
        Ok(Self {
            database,
            database_identity: FileIdentity::of(&db_metadata),
            vm_root,
            vm_root_identity: FileIdentity::of(&vm_metadata),
        })
    }
}

pub(crate) struct AttemptBudget {
    directory: PathBuf,
    uid: u32,
    _lock: File,
    register: Register,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
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
            || ((register.cleanup_requested
                || register.owner.is_some()
                || register.runtime.is_some())
                && register.pending.is_none())
            || register
                .pending
                .as_ref()
                .is_some_and(|pending| register.admitted.last() != Some(pending))
        {
            return Err(io::Error::other("invalid sandbox attempt register"));
        }
        Ok(Self {
            directory: directory.into(),
            uid: owner,
            _lock: lock,
            register,
        })
    }

    fn attempt(&self, id: &str) -> Result<Attempt, String> {
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
        reap: impl FnOnce(&str) -> Result<(), String>,
        verify_unused: impl FnOnce() -> Result<RuntimeStorage, String>,
    ) -> Result<File, String> {
        let attempt = self.attempt(id)?;
        self.retry_cleanup(|id, _| reap(id))?;
        if attempt != Attempt::Unknown {
            return Err("sandbox attempt was already admitted".into());
        }
        if self.register.admitted.len() == self.register.limit {
            return Err("sandbox attempt budget exhausted".into());
        }
        if self.register.pending.is_some() {
            return Err("previous sandbox attempt still requires cleanup".into());
        }
        let runtime = verify_unused()?;
        let owner = self
            .try_lock_owner(None)?
            .ok_or("previous sandbox owner still holds its lock")?;
        let metadata = owner.metadata().map_err(|error| error.to_string())?;
        self.register.owner = Some(FileIdentity::of(&metadata));
        self.register.runtime = Some(runtime);
        self.register.admitted.push(id.into());
        self.register.pending = Some(id.into());
        self.persist()?;
        Ok(owner)
    }

    pub(crate) fn cleanup(
        &mut self,
        id: &str,
        verify_absent: impl FnOnce(bool) -> Result<(), String>,
        reap: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<(), String> {
        match self.attempt(id)? {
            Attempt::Unknown => return verify_absent(false),
            Attempt::Retired => return verify_absent(true),
            Attempt::Pending => {}
        }

        // Persist Delete's intent before touching the original VM. Later
        // Creates can then resume cleanup without treating a live VM as stale.
        if !self.register.cleanup_requested {
            self.register.cleanup_requested = true;
            self.persist()?;
        }
        self.retry_cleanup(|id, _| reap(id))?;
        if self.register.pending.is_some() {
            return Err(format!("sandbox {id} still has an active owner"));
        }
        Ok(())
    }

    /// Deliver a saved Delete to the shim that holds the original owner file.
    pub(crate) fn deliver_cleanup_request(
        self,
        id: &str,
        owner: &File,
        cleanup: impl FnOnce() -> Result<(), String>,
    ) -> Result<bool, String> {
        if !self.register.cleanup_requested || self.register.pending.as_deref() != Some(id) {
            return Ok(false);
        }
        let metadata = owner.metadata().map_err(|error| error.to_string())?;
        if self.register.owner != Some(FileIdentity::of(&metadata)) {
            return Err("saved sandbox cleanup does not match the owner file".into());
        }
        // The owner must release its share writers and re-enter cleanup
        // without holding the register lock.
        drop(self);
        cleanup()?;
        Ok(true)
    }

    /// The node timer calls this independently of any Create or Delete.
    pub(crate) fn reconcile(
        &mut self,
        observe_runtime: impl FnOnce() -> Result<RuntimeStorage, String>,
        reap: impl FnOnce(&str) -> Result<(), String>,
    ) -> Result<(), String> {
        self.retry_cleanup(|id, expected| {
            let expected = expected.ok_or("original sandbox has no recorded runtime storage")?;
            if &observe_runtime()? != expected {
                return Err("worker runtime storage differs from the admitted sandbox".into());
            }
            reap(id)
        })
    }

    fn retry_cleanup(
        &mut self,
        reap: impl FnOnce(&str, Option<&RuntimeStorage>) -> Result<(), String>,
    ) -> Result<(), String> {
        let Some(id) = self.register.pending.as_deref() else {
            return Ok(());
        };
        // A tracked owner may still have share writers even after a Delete
        // request. Hold the lock through cleanup and retirement.
        let _owner = match self.register.owner {
            Some(expected) => {
                let Some(owner) = self.try_lock_owner(Some(expected))? else {
                    return Ok(());
                };
                Some(owner)
            }
            None if self.register.cleanup_requested => None,
            None => return Ok(()),
        };
        reap(id, self.register.runtime.as_ref())
            .map_err(|error| format!("cleanup of sandbox {id}: {error}"))?;
        self.register.pending = None;
        self.register.cleanup_requested = false;
        self.register.owner = None;
        self.register.runtime = None;
        self.persist()
    }

    fn try_lock_owner(&self, expected: Option<FileIdentity>) -> Result<Option<File>, String> {
        let path = self.directory.join(OWNER_LOCK);
        let file = match open_private(&path, self.uid) {
            Err(error) if error.kind() == io::ErrorKind::NotFound && expected.is_none() => {
                // The register lock serializes creation of this fixed inode.
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .and_then(|file| {
                        file.sync_all()?;
                        Ok(file)
                    })
            }
            result => result,
        }
        .map_err(|error| format!("open sandbox owner lock: {error}"))?;
        if let Some(expected) = expected {
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            let actual = FileIdentity::of(&metadata);
            if actual != expected {
                return Err("sandbox owner lock identity changed".into());
            }
        }
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(format!("lock sandbox owner: {error}")),
        }
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
        File::create(directory.path().join("runtime.db")).unwrap();
        fs::create_dir(directory.path().join("vms")).unwrap();
        directory
    }

    fn runtime_storage(path: &Path) -> Result<RuntimeStorage, String> {
        RuntimeStorage::read(&path.join("runtime.db"), &path.join("vms"))
            .map_err(|error| error.to_string())
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lost_ack_and_cleanup_keep_the_debit() {
        let directory = fixture(1);
        let id = "a".repeat(64);
        let owner = AttemptBudget::open(directory.path())
            .unwrap()
            .admit(
                &id,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();
        let mut restarted = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Pending);
        assert_eq!(
            restarted
                .admit(&id, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "sandbox attempt was already admitted"
        );
        let refused = "b".repeat(64);
        assert_eq!(
            restarted
                .admit(&refused, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "sandbox attempt budget exhausted"
        );
        assert_eq!(restarted.attempt(&refused).unwrap(), Attempt::Unknown);
        assert_eq!(
            restarted
                .cleanup(&id, |_| unreachable!(), |_| unreachable!())
                .unwrap_err(),
            format!("sandbox {id} still has an active owner")
        );
        assert!(restarted.register.cleanup_requested);
        restarted
            .reconcile(|| unreachable!(), |_| unreachable!())
            .unwrap();
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Pending);
        drop(restarted);
        drop(owner);
        let mut restarted = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Pending);
        assert_eq!(
            restarted
                .admit(
                    &refused,
                    |original| {
                        assert_eq!(original, id);
                        Ok(())
                    },
                    || unreachable!(),
                )
                .unwrap_err(),
            "sandbox attempt budget exhausted"
        );
        assert_eq!(restarted.attempt(&id).unwrap(), Attempt::Retired);
        assert_eq!(restarted.register.admitted, [id]);
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
                AttemptBudget::open(&path).unwrap().admit(
                    &prefix.repeat(64),
                    |_| unreachable!(),
                    || runtime_storage(&path),
                )
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

    #[test]
    fn interrupted_cleanup_is_retried_before_next_admission() {
        let directory = fixture(2);
        let original = "a".repeat(64);
        let next = "b".repeat(64);
        let mut budget = AttemptBudget::open(directory.path()).unwrap();
        let owner = budget
            .admit(
                &original,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();
        budget
            .cleanup(
                &next,
                |allow_lock| {
                    assert!(!allow_lock);
                    Ok(())
                },
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(
            budget
                .admit(&next, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "previous sandbox attempt still requires cleanup"
        );
        drop(owner);
        let temporary_error = format!("cleanup of sandbox {original}: temporary cleanup failure");
        assert_eq!(
            budget
                .cleanup(
                    &original,
                    |_| unreachable!(),
                    |id| {
                        assert_eq!(id, original);
                        Err("temporary cleanup failure".into())
                    },
                )
                .unwrap_err(),
            temporary_error
        );
        drop(budget);

        let mut reopened = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(
            reopened
                .admit(
                    &next,
                    |id| {
                        assert_eq!(id, original);
                        Err("temporary cleanup failure".into())
                    },
                    || unreachable!(),
                )
                .unwrap_err(),
            temporary_error
        );
        drop(reopened);

        let mut reopened = AttemptBudget::open(directory.path()).unwrap();
        reopened
            .admit(
                &next,
                |id| {
                    assert_eq!(id, original);
                    Ok(())
                },
                || runtime_storage(directory.path()),
            )
            .expect("recover the original cleanup and admit the replacement");
        assert_eq!(reopened.register.admitted, [original.clone(), next.clone()]);
        assert_eq!(reopened.attempt(&original).unwrap(), Attempt::Retired);
        assert_eq!(reopened.attempt(&next).unwrap(), Attempt::Pending);
    }

    #[test]
    fn cleanup_recovers_after_its_register_update_fails() {
        let directory = fixture(2);
        let original = "a".repeat(64);
        let next = "b".repeat(64);
        let mut budget = AttemptBudget::open(directory.path()).unwrap();
        let owner = budget
            .admit(
                &original,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();

        let blocked_update = directory.path().join(NEXT_REGISTER);
        fs::create_dir(&blocked_update).unwrap();
        let error = budget
            .cleanup(&original, |_| unreachable!(), |_| unreachable!())
            .unwrap_err();
        assert!(error.starts_with("commit sandbox attempt register:"));
        drop(budget);
        fs::remove_dir(blocked_update).unwrap();

        let mut reopened = AttemptBudget::open(directory.path()).unwrap();
        assert!(!reopened.register.cleanup_requested);
        assert_eq!(
            reopened
                .admit(&next, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "previous sandbox attempt still requires cleanup"
        );
        drop(owner);
        reopened
            .admit(
                &next,
                |id| {
                    assert_eq!(id, original);
                    Ok(())
                },
                || runtime_storage(directory.path()),
            )
            .expect("recover the original cleanup after the register write failure");
        assert_eq!(reopened.attempt(&original).unwrap(), Attempt::Retired);
        assert_eq!(reopened.register.admitted, [original, next]);
    }

    #[test]
    fn replaced_owner_lock_is_not_evidence_of_abandonment() {
        let directory = fixture(2);
        let original = "a".repeat(64);
        let next = "b".repeat(64);
        let mut budget = AttemptBudget::open(directory.path()).unwrap();
        let _owner = budget
            .admit(
                &original,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();

        let path = directory.path().join(OWNER_LOCK);
        fs::rename(&path, directory.path().join("original-owner")).unwrap();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        assert_eq!(
            budget
                .admit(&next, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "sandbox owner lock identity changed"
        );
        assert_eq!(budget.register.admitted, [original]);
    }

    #[test]
    fn legacy_pending_attempt_requires_the_original_delete() {
        let directory = fixture(2);
        let original = "a".repeat(64);
        let next = "b".repeat(64);
        fs::write(
            directory.path().join(REGISTER),
            format!(
                r#"{{"version":1,"limit":2,"admitted":["{original}"],"pending":"{original}"}}"#
            ),
        )
        .unwrap();
        let mut budget = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(
            budget
                .admit(&next, |_| unreachable!(), || unreachable!())
                .unwrap_err(),
            "previous sandbox attempt still requires cleanup"
        );
        budget
            .cleanup(
                &original,
                |_| unreachable!(),
                |id| {
                    assert_eq!(id, original);
                    Ok(())
                },
            )
            .unwrap();
        let _next_owner = budget
            .admit(
                &next,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();
        assert_eq!(budget.register.admitted, [original, next]);
    }

    #[test]
    fn abandoned_attempt_recovers_without_new_admission() {
        let directory = fixture(1);
        let original = "a".repeat(64);
        let mut budget = AttemptBudget::open(directory.path()).unwrap();
        let owner = budget
            .admit(
                &original,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();
        budget
            .reconcile(|| unreachable!(), |_| unreachable!())
            .unwrap();
        assert_eq!(budget.attempt(&original), Ok(Attempt::Pending));
        drop(owner);
        assert!(budget
            .cleanup(
                &original,
                |_| unreachable!(),
                |_| Err("temporary cleanup failure".into())
            )
            .is_err());
        drop(budget);

        // The gateway only observes until the original attempt settles.
        // No successor is submitted to the shim in this test.
        let mut reopened = AttemptBudget::open(directory.path()).unwrap();
        let alternate_worker = fixture(1);
        let error = reopened
            .reconcile(
                || runtime_storage(alternate_worker.path()),
                |_| unreachable!(),
            )
            .unwrap_err();
        assert!(error.ends_with("worker runtime storage differs from the admitted sandbox"));
        assert_eq!(reopened.attempt(&original), Ok(Attempt::Pending));
        reopened
            .reconcile(
                || runtime_storage(directory.path()),
                |id| {
                    assert_eq!(id, original);
                    Ok(())
                },
            )
            .unwrap();
        drop(reopened);
        let reopened = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(
            reopened.attempt(&original),
            Ok(Attempt::Retired),
            "the worker must settle the original before the gateway can admit again"
        );
        assert_eq!(reopened.register.admitted, [original]);
    }

    #[test]
    fn disconnected_live_owner_can_settle_saved_delete() {
        let directory = fixture(1);
        let original = "a".repeat(64);
        let owner = AttemptBudget::open(directory.path())
            .unwrap()
            .admit(
                &original,
                |_| unreachable!(),
                || runtime_storage(directory.path()),
            )
            .unwrap();

        let mut disconnected = AttemptBudget::open(directory.path()).unwrap();
        assert_eq!(
            disconnected
                .cleanup(&original, |_| unreachable!(), |_| unreachable!())
                .unwrap_err(),
            format!("sandbox {original} still has an active owner")
        );
        drop(disconnected);

        // The shim is alive after the disconnect. It still holds the owner
        // descriptor, and the caller sends no further task RPC.
        let mut timer = AttemptBudget::open(directory.path()).unwrap();
        timer
            .reconcile(|| unreachable!(), |_| unreachable!())
            .unwrap();
        assert_eq!(timer.attempt(&original), Ok(Attempt::Pending));
        assert!(!timer
            .deliver_cleanup_request(&"b".repeat(64), &owner, || unreachable!())
            .unwrap());
        let unrelated = File::open(directory.path().join("lock")).unwrap();
        let timer = AttemptBudget::open(directory.path()).unwrap();
        assert!(timer
            .deliver_cleanup_request(&original, &unrelated, || unreachable!())
            .is_err());

        let saved = AttemptBudget::open(directory.path()).unwrap();
        assert!(saved
            .deliver_cleanup_request(&original, &owner, || {
                owner.unlock().unwrap();
                let reopened = AttemptBudget::open(directory.path()).unwrap();
                assert_eq!(reopened.attempt(&original), Ok(Attempt::Pending));
                Ok(())
            })
            .unwrap());
        let mut timer = AttemptBudget::open(directory.path()).unwrap();
        timer
            .reconcile(
                || runtime_storage(directory.path()),
                |id| {
                    assert_eq!(id, original);
                    Ok(())
                },
            )
            .unwrap();
        timer
            .cleanup(
                &original,
                |allow_lock| {
                    assert!(allow_lock);
                    Ok(())
                },
                |_| unreachable!(),
            )
            .unwrap();
        assert_eq!(
            timer.attempt(&original),
            Ok(Attempt::Retired),
            "a saved Delete must reach the live owner without another task RPC"
        );
        assert_eq!(timer.register.admitted, [original]);
        drop(owner);
    }
}
