//! A private, verified executable snapshot for one stdio child.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::config::{binary_sha256, UNAVAILABLE_SHA256};

const MAX_PROGRAM_BYTES: u64 = 512 * 1024 * 1024;

/// System binaries on macOS may only run from their original sealed volume.
/// Everything else must run from a verified private copy.
pub(super) enum PreparedProgram {
    #[cfg(target_os = "macos")]
    Sealed(PathBuf),
    Copy(Snapshot),
}

impl PreparedProgram {
    pub(super) fn create(source: &Path, parent: &Path, expected: &str) -> io::Result<Self> {
        #[cfg(target_os = "macos")]
        if let Some(canonical) = sealed_system_program(source, expected) {
            return Ok(Self::Sealed(canonical));
        }
        Snapshot::create(source, parent, expected).map(Self::Copy)
    }

    pub(super) fn program(&self) -> &Path {
        match self {
            #[cfg(target_os = "macos")]
            Self::Sealed(path) => path,
            Self::Copy(snapshot) => snapshot.program(),
        }
    }
}

#[cfg(target_os = "macos")]
fn sealed_system_program(source: &Path, expected: &str) -> Option<PathBuf> {
    let canonical = source.canonicalize().ok()?;
    // APFS firmlinks can report the root device for writable Data files, so a
    // device check alone is insufficient. Limit the exception to Apple's
    // system binary directories as well as checking the sealed root.
    let system_directory = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
        .iter()
        .any(|dir| canonical.starts_with(dir));
    let same_device = fs::metadata(&canonical)
        .and_then(|file| fs::metadata("/").map(|root| file.dev() == root.dev()))
        .unwrap_or(false);
    if !system_directory || !same_device || expected == UNAVAILABLE_SHA256 {
        return None;
    }
    let sealed_root = std::process::Command::new("/sbin/mount")
        .env_clear()
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|mounts| {
            let sealed = mounts.lines().any(|line| {
                line.contains(" on / (apfs,")
                    && line.contains("sealed")
                    && line.contains("read-only")
            });
            let overlaid = mounts.lines().any(|line| {
                line.split_once(" on ")
                    .and_then(|(_, rest)| rest.split_once(" ("))
                    .is_some_and(|(mount, _)| mount != "/" && canonical.starts_with(mount))
            });
            sealed && !overlaid
        });
    (sealed_root && binary_sha256(&canonical) == expected).then_some(canonical)
}

/// Kept alive until the child exits, including for interpreter scripts.
pub(super) struct Snapshot {
    dir: PathBuf,
    program: PathBuf,
}

impl Snapshot {
    pub(super) fn create(source: &Path, parent: &Path, expected: &str) -> io::Result<Self> {
        if expected == UNAVAILABLE_SHA256 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unhashable program",
            ));
        }
        let filename = source.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "program has no filename")
        })?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let dir = parent.join(format!(".aux-mcp-exec-{name}"));
        DirBuilder::new().mode(0o700).create(&dir)?;
        let program = dir.join(filename);
        let snapshot = Self { dir, program };
        let original = File::open(source)?;
        let metadata = original.metadata()?;
        let executable = std::process::Command::new("/bin/test")
            .env_clear()
            .arg("-x")
            .arg(source)
            .status()?
            .success();
        let current = fs::metadata(source)?;
        if !metadata.is_file()
            || !executable
            || (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
            ) != (
                current.dev(),
                current.ino(),
                current.mode(),
                current.uid(),
                current.gid(),
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "program is not executable",
            ));
        }
        if metadata.len() > MAX_PROGRAM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "program is too large",
            ));
        }
        let mut copy = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&snapshot.program)?;
        if io::copy(&mut original.take(MAX_PROGRAM_BYTES + 1), &mut copy)? > MAX_PROGRAM_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "program is too large",
            ));
        }
        drop(copy);
        fs::set_permissions(&snapshot.program, fs::Permissions::from_mode(0o500))?;
        fs::set_permissions(&snapshot.dir, fs::Permissions::from_mode(0o500))?;
        if binary_sha256(&snapshot.program) != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "program hash changed",
            ));
        }
        Ok(snapshot)
    }

    pub(super) fn program(&self) -> &Path {
        &self.program
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_preserves_verified_bytes_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("server");
        fs::write(&program, b"original").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let sha = binary_sha256(&program);
        let snapshot = Snapshot::create(&program, dir.path(), &sha).unwrap();
        let snapshot_dir = snapshot.dir.clone();
        fs::write(&program, b"replacement").unwrap();
        assert_eq!(fs::read(snapshot.program()).unwrap(), b"original");
        assert!(Snapshot::create(&program, dir.path(), &sha).is_err());
        drop(snapshot);
        assert!(!snapshot_dir.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn snapshot_refuses_non_executable_or_oversized_sources() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("server");
        fs::write(&program, b"program").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o610)).unwrap();
        assert!(Snapshot::create(&program, dir.path(), "unused").is_err());
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        File::options()
            .write(true)
            .open(&program)
            .unwrap()
            .set_len(MAX_PROGRAM_BYTES + 1)
            .unwrap();
        assert!(Snapshot::create(&program, dir.path(), "unused").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sealed_system_program_resolves_symlinks_and_requires_matching_hash() {
        let system = Path::new("/bin/sh");
        let sha = binary_sha256(system);
        if let Some(canonical) = sealed_system_program(system, &sha) {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join("sh");
            std::os::unix::fs::symlink(system, &link).unwrap();
            assert_eq!(sealed_system_program(&link, &sha), Some(canonical));
            assert!(sealed_system_program(&link, "wrong-hash").is_none());
            let ordinary = dir.path().join("ordinary");
            fs::write(&ordinary, b"ordinary").unwrap();
            assert!(sealed_system_program(&ordinary, &binary_sha256(&ordinary)).is_none());
        }
    }
}
