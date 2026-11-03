//! The system paths and Mach services a runtime needs to start.

/// System directories a runtime reads to start: dyld, the C++/Foundation
/// libraries, the framework bundles and the TLS roots.
///
/// The dyld shared cache lives under the Preboot Cryptexes volume on current
/// macOS; without read access to it every child dies in dyld before `main`.
pub(super) const SYSTEM_READ_DIRS: &[&str] = &[
    "/usr/lib",
    "/usr/share",
    "/System/Library",
    "/System/Library/dyld",
    "/System/Volumes/Preboot/Cryptexes",
    "/System/Cryptexes",
    "/Library/Apple",
    "/private/var/db/dyld",
    "/private/etc/ssl",
];

/// Device nodes a runtime opens: the null/random sinks and the three standard
/// streams.
pub(super) const SYSTEM_READ_FILES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
];

/// Mach services common runtimes look up while starting (CoreFoundation's
/// preferences and logging daemons). Nothing here exposes owner data.
pub(super) const MACH_SERVICES: &[&str] = &[
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.cfprefsd.agent",
    "com.apple.system.logger",
    "com.apple.logd",
];
