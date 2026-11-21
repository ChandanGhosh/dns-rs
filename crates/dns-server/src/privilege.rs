//! Drop root privileges after privileged resources have been created.
//!
//! The daemon may need root to bind port 53 and to read root-owned TLS keys,
//! trust anchors, and zone files. Once listeners and the control socket exist,
//! `username` selects an unprivileged account and the process permanently
//! switches to it. The order matters: supplementary groups and the primary
//! group must be dropped before the user ID, because `setuid` removes the
//! ability to change either afterwards.
//!
//! This module is Unix-only. On other platforms the daemon logs a warning and
//! keeps running as the user that started it.

use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::unistd::{Gid, Uid, User, chown, initgroups, setgid, setuid};

/// A failure while resolving, chowning for, or switching to the target user.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PrivilegeError {
    /// The configured name is not present in the system user database.
    #[error("user {0:?} does not exist")]
    UnknownUser(String),
    /// The user database could not be queried.
    #[error("cannot resolve user {user:?}: {source}")]
    Lookup {
        /// Configured user name.
        user: String,
        /// Underlying lookup error.
        #[source]
        source: Errno,
    },
    /// The user name contained a NUL byte and cannot be passed to libc.
    #[error("user name contains a NUL byte")]
    NulName,
    /// The process was not privileged enough to switch to the target user.
    #[error("cannot drop privileges to {user:?}: the process is not root (euid {euid})")]
    NotRoot {
        /// Target user name.
        user: String,
        /// Effective user ID at the time of the attempt.
        euid: u32,
    },
    /// A setuid/setgid/initgroups call failed.
    #[error("cannot drop privileges to {user:?}: {source}")]
    Drop {
        /// Target user name.
        user: String,
        /// Underlying system error.
        #[source]
        source: Errno,
    },
    /// The kernel did not apply the requested IDs.
    #[error("privilege drop to {user:?} did not take effect (uid {uid}, gid {gid})")]
    NotApplied {
        /// Target user name.
        user: String,
        /// Effective user ID after the drop.
        uid: u32,
        /// Effective group ID after the drop.
        gid: u32,
    },
    /// A path could not be inspected before changing its ownership.
    #[error("cannot inspect {path}: {source}")]
    Inspect {
        /// Path that could not be inspected.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A file or socket could not be handed to the target user.
    #[error("cannot change ownership of {path} to {user:?}: {source}")]
    Chown {
        /// Path whose ownership could not be changed.
        path: PathBuf,
        /// Target user name.
        user: String,
        /// Underlying system error.
        #[source]
        source: Errno,
    },
}

/// The account the daemon switches to after startup.
#[derive(Debug, Clone)]
pub(crate) struct TargetUser {
    /// Name in the form libc expects for `initgroups`.
    name: CString,
    /// Name used in diagnostics.
    display: String,
    /// User ID to switch to.
    uid: Uid,
    /// Primary group ID to switch to.
    gid: Gid,
}

impl TargetUser {
    /// Resolve a configured user name through the system user database.
    ///
    /// # Errors
    ///
    /// Returns [`PrivilegeError::UnknownUser`] when the name does not exist and
    /// [`PrivilegeError::Lookup`] when the lookup itself fails.
    pub(crate) fn resolve(name: &str) -> Result<Self, PrivilegeError> {
        let user = User::from_name(name)
            .map_err(|source| PrivilegeError::Lookup {
                user: name.to_owned(),
                source,
            })?
            .ok_or_else(|| PrivilegeError::UnknownUser(name.to_owned()))?;
        // The user database cannot contain NUL bytes, so this only fails for
        // a corrupted entry. Treat it as a lookup failure rather than panicking.
        let name = CString::new(user.name.clone()).map_err(|_| PrivilegeError::NulName)?;
        Ok(Self {
            name,
            display: user.name,
            uid: user.uid,
            gid: user.gid,
        })
    }

    /// The name used in logs and error messages.
    pub(crate) fn display_name(&self) -> &str {
        &self.display
    }

    /// Whether the target account is root and therefore grants no reduction.
    pub(crate) fn is_root(&self) -> bool {
        self.uid.is_root()
    }

    /// Change `path` to be owned by the target user and group.
    ///
    /// Already-owned paths are left alone, so this also works when the daemon
    /// starts as the target user without root.
    ///
    /// # Errors
    ///
    /// Returns [`PrivilegeError::Inspect`] when the metadata cannot be read and
    /// [`PrivilegeError::Chown`] when the ownership change fails.
    pub(crate) fn ensure_owner(&self, path: &Path) -> Result<(), PrivilegeError> {
        let metadata = std::fs::metadata(path).map_err(|source| PrivilegeError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.uid() == self.uid.as_raw() && metadata.gid() == self.gid.as_raw() {
            return Ok(());
        }
        chown(path, Some(self.uid), Some(self.gid)).map_err(|source| PrivilegeError::Chown {
            path: path.to_path_buf(),
            user: self.display.clone(),
            source,
        })
    }

    /// Permanently switch the process to the target user and group.
    ///
    /// Supplementary groups are replaced with the target user's groups, then
    /// the primary group and user IDs are set. The effective IDs are verified
    /// before returning so the daemon never continues as root after a failed
    /// or partial switch.
    ///
    /// Calling this when the process already runs as the target user is a
    /// no-op, which keeps `username` usable in a container that already runs
    /// unprivileged.
    ///
    /// # Errors
    ///
    /// Returns [`PrivilegeError::NotRoot`] when a switch is required but the
    /// process is not root, [`PrivilegeError::Drop`] when a system call fails,
    /// and [`PrivilegeError::NotApplied`] when the effective IDs do not match
    /// the target.
    pub(crate) fn drop_privileges(&self) -> Result<(), PrivilegeError> {
        let euid = Uid::effective();
        let egid = Gid::effective();
        if euid == self.uid && egid == self.gid {
            return Ok(());
        }
        if !euid.is_root() {
            return Err(PrivilegeError::NotRoot {
                user: self.display.clone(),
                euid: euid.as_raw(),
            });
        }

        let drop = |source| PrivilegeError::Drop {
            user: self.display.clone(),
            source,
        };
        initgroups(&self.name, self.gid).map_err(drop)?;
        setgid(self.gid).map_err(drop)?;
        setuid(self.uid).map_err(drop)?;

        let uid = Uid::effective();
        let gid = Gid::effective();
        if uid != self.uid || gid != self.gid {
            return Err(PrivilegeError::NotApplied {
                user: self.display.clone(),
                uid: uid.as_raw(),
                gid: gid.as_raw(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use nix::unistd::{Gid, Uid, User};

    use super::{PrivilegeError, TargetUser};

    fn current_user() -> Option<User> {
        User::from_uid(Uid::effective()).expect("lookup current user")
    }

    #[test]
    fn resolves_the_current_user() {
        let Some(user) = current_user() else {
            return;
        };
        let target = TargetUser::resolve(&user.name).expect("resolve current user");
        assert_eq!(target.uid, user.uid);
        assert_eq!(target.gid, user.gid);
        assert_eq!(target.display_name(), user.name);
    }

    #[test]
    fn unknown_user_is_rejected() {
        let name = format!("dns-rs-no-such-user-{}", std::process::id());
        assert!(matches!(
            TargetUser::resolve(&name),
            Err(PrivilegeError::UnknownUser(missing)) if missing == name
        ));
    }

    #[test]
    fn dropping_to_the_current_user_is_a_noop() {
        let Some(user) = current_user() else {
            return;
        };
        // A process can run with a primary group that differs from its passwd
        // entry; that case needs root and is covered by the NotRoot path.
        if Gid::effective() != user.gid {
            return;
        }
        let target = TargetUser::resolve(&user.name).expect("resolve current user");
        target.drop_privileges().expect("no-op drop");
    }

    #[test]
    fn ensure_owner_accepts_an_already_owned_path() {
        let Some(user) = current_user() else {
            return;
        };
        if Gid::effective() != user.gid {
            return;
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("state");
        fs::write(&path, b"state").expect("write state");
        let target = TargetUser::resolve(&user.name).expect("resolve current user");
        target.ensure_owner(&path).expect("already owned");
        let metadata = fs::metadata(&path).expect("metadata");
        assert_eq!(metadata.uid(), user.uid.as_raw());
        assert_eq!(metadata.gid(), user.gid.as_raw());
    }
}
