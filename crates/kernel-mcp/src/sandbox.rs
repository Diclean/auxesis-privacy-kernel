//! macOS Seatbelt profile for a mounted stdio extension.
//!
//! An extension runs under `sandbox-exec` with a profile generated from its
//! catalog entry. The profile is deny-by-default and deliberately narrow:
//!
//! - **exec**: the extension's own install dir (read-only) and the exact
//!   runtime interpreter binaries the entry names — never a runtime
//!   *directory*, and never the extension's `work/` data dir, which is denied
//!   after the install-dir allow (rules are last-match-wins);
//! - **read**: the install dir, the runtime paths and the system libraries a
//!   runtime needs to start (dyld shared cache, `/usr/lib`, frameworks, TLS
//!   certs), plus the root directory literal dyld needs;
//! - **metadata**: only the allowed trees and the literal path components that
//!   lead to them. A global `file-read-metadata` would leak the existence,
//!   size and mtime of *any* file, including the owner's `~`;
//! - **write**: the extension's own `work/` dir only — never its install dir,
//!   never another extension, never the Auxesis home (deny default covers it);
//! - **process-info**: denied globally and allowed back for `self` only, so a
//!   child cannot read another process's argv/env through `sysctl`
//!   `KERN_PROCARGS2` or `proc_pidpath`;
//! - **file-map-executable**: denied on `work/`, so a dylib dropped there
//!   cannot be `dlopen`ed even though the tree is readable;
//! - **iokit**: `iokit-get-properties` is denied, so hardware identifiers such
//!   as `IOPlatformSerialNumber` stay unreadable;
//! - **network**: with `proxy_port = None` the profile carries **no** network
//!   rule at all, so `(deny default)` denies every socket, loopback included.
//!   With `proxy_port = Some(p)` it allows **TCP** outbound traffic to the
//!   IPv4 loopback address on `p` only (`tcp4`, so `::1` and UDP stay denied)
//!   — the egress proxy (`kernel-net::proxy`) enforces the entry's host
//!   allowlist from there. Seatbelt cannot filter by host name, so this one
//!   loopback port is the whole network surface.
//!
//! Paths are quoted as Scheme strings with backslashes and quotes escaped, and
//! control characters dropped, so a path can never shape the profile. A
//! dropped character makes the rule match no real path, which fails closed.
//! The kernel matches the *canonical* path, so callers pass canonical dirs.
//!
//! # Accepted limitations
//!
//! - `com.apple.system.opendirectoryd.libinfo` is allowed for Foundation/dyld
//!   startup. It lets a child enumerate local user and group directory records
//!   (names, uids, home paths) through opendirectoryd. No file contents or
//!   credentials are exposed, and the runtime cannot start without it, so this
//!   is accepted.
//! - The installer (app side) must refuse symlinks and hardlinks inside an
//!   extension archive before extraction (implemented in the app WO-13b). The
//!   sandbox trusts `install_dir` to hold the vetted tree; a link that escaped
//!   it would otherwise let a path outside the install tree be read or
//!   executed.

// The submodules are private on purpose: every item below is re-exported at
// this path, so `crate::sandbox::…` is exactly what it was before the
// split, and no new public path appears.
mod paths;
mod profile;
mod spec;
mod system;

#[cfg(test)]
mod tests;

pub use profile::seatbelt_profile;
pub use spec::SandboxSpec;
