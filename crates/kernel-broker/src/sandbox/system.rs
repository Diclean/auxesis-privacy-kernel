//! The system trees, package program directories and read-back paths the
//! profile grants, and the sysctl names it allows back.

/// Read + execute allowlist: the system trees commands need. Never writable.
pub(super) const SYSTEM_TREES: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library/Apple",
    "/Library/Developer/CommandLineTools",
    "/Library/Frameworks/Python.framework",
];

/// The only directories inside the package prefixes (`/opt/homebrew`,
/// `/usr/local`) that are read + execute allowed: the program directories the
/// package managers put executables, libraries and headers in. The prefixes
/// themselves are never allowed wholesale — `var`, `etc`, `Library` and
/// `Caskroom` hold service state, datasets, git checkouts and configs.
pub(super) const PACKAGE_DIRS: &[&str] = &[
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/homebrew/opt",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/lib",
    "/opt/homebrew/include",
    "/opt/homebrew/share",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/local/opt",
    "/usr/local/Cellar",
    "/usr/local/lib",
    "/usr/local/include",
    "/usr/local/share",
];

/// State/config directories inside the package prefixes that stay explicitly
/// denied even if a future edit widens the allows: live service logs and
/// databases (`var`), package configs (`etc`), cached data (`Library`) and
/// downloaded casks (`Caskroom`).
pub(super) const PACKAGE_DENIED_DIRS: &[&str] = &[
    "/opt/homebrew/var",
    "/opt/homebrew/etc",
    "/opt/homebrew/Library",
    "/opt/homebrew/Caskroom",
    "/usr/local/var",
    "/usr/local/etc",
    "/usr/local/Library",
    "/usr/local/Caskroom",
];

/// Specific files inside otherwise-denied package `etc` trees that common
/// toolchains read at startup, emitted as read-only allow-backs *after* the
/// package deny. Homebrew's OpenSSL sets `OPENSSLDIR=/opt/homebrew/etc/...`
/// and node/npm/pnpm/tsc abort in `BIO_new_file` when they cannot open the
/// config; the CA bundle is what the config points at. Keep this list literal
/// and path-specific — the surrounding `etc` tree holds service configs and
/// must stay denied.
pub(super) const PACKAGE_READ_BACK_FILES: &[&str] = &[
    "/opt/homebrew/etc/openssl@3/openssl.cnf",
    "/opt/homebrew/etc/openssl@1.1/openssl.cnf",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/usr/local/etc/openssl@3/openssl.cnf",
    "/usr/local/etc/openssl@1.1/openssl.cnf",
    "/usr/local/etc/ca-certificates/cert.pem",
];

/// Read-only directory allow-backs *after* the package deny: only
/// package-shipped public certificate stores (never an OpenSSL keg's
/// `private` directory) and the macOS system Ruby gems tree, which rubygems
/// globs at interpreter startup — without it every `ruby`/`gem`/`bundler`
/// call dies with `EPERM`.
///
/// Homebrew's own `Library/Homebrew` tree is here too —
/// that is where the `brew` executable lives and where `brew --version`,
/// `brew list` and `brew info` read their own code and formula metadata from.
/// Without it every `brew` call dies on `EPERM`. The rest of `Library` stays
/// denied; `var`, `etc` and `Caskroom` are untouched.
pub(super) const READ_BACK_DIRS: &[&str] = &[
    "/opt/homebrew/etc/openssl@3/certs",
    "/opt/homebrew/etc/openssl@1.1/certs",
    "/opt/homebrew/etc/ca-certificates",
    "/opt/homebrew/Library/Homebrew",
    "/usr/local/etc/openssl@3/certs",
    "/usr/local/etc/openssl@1.1/certs",
    "/usr/local/etc/ca-certificates",
    "/usr/local/Library/Homebrew",
    "/Library/Ruby",
];

/// Directories whose programs may be **executed** after the deny, in addition
/// to the read-back above.
///
/// `brew` is a shell script that re-execs its own vendored Ruby out of
/// `Library/Homebrew` (`vendor/portable-ruby/current/bin/ruby`); read access
/// alone still fails when that binary is run. Both trees are read-only: the
/// profile never grants a write under them, so `brew install`/`brew upgrade`
/// can only touch the workspace and the per-call temp dir.
pub(super) const EXEC_READ_BACK_DIRS: &[&str] = &[
    "/opt/homebrew/Library/Homebrew",
    "/usr/local/Library/Homebrew",
];

/// Extra read-only trees outside the system ones: dyld cache, timezone data,
/// TLS certificates and the device nodes.
pub(super) const EXTRA_READ_TREES: &[&str] = &[
    "/private/var/db/dyld",
    "/private/var/db/timezone",
    "/private/etc/ssl",
    "/dev",
];

/// Individual `/etc` files common commands read (name resolution, local time,
/// service/protocol lookups).
pub(super) const EXTRA_READ_FILES: &[&str] = &[
    "/private/etc/hosts",
    "/private/etc/resolv.conf",
    "/private/etc/localtime",
    "/private/etc/services",
    "/private/etc/protocols",
];

/// The only sysctl names allowed back after the global `(deny sysctl-read)`.
/// Derived empirically from the command matrix: libc's `sysconf`, Python's
/// `os.cpu_count`/`multiprocessing`, `uname`, `hostname` and `perl`/`shasum`
/// need exactly these; everything else (the process table, VM internals,
/// kernel boot/proc state) stays denied.
pub(super) const ALLOWED_SYSCTL_NAMES: &[&str] = &[
    "hw.machine",
    "hw.memsize",
    "hw.ncpu",
    "kern.hostname",
    "kern.osrelease",
    "kern.ostype",
    "kern.osversion",
    "kern.version",
];

/// Sysctl prefixes allowed back after the global deny.
///
/// - `sysctl.` is the `sysctl(8)` CLI's own metadata namespace: the CLI asks
///   the kernel for an OID's name/format before reading a value, and those
///   lookups carry no value at all. Without it the CLI cannot even print an
///   allowed name.
/// - `hw.pagesize` covers `hw.pagesize` and `hw.pagesize32`; libc's
///   `sysconf(_SC_PAGESIZE)` reads the page size through a path that exact
///   `sysctl-name` filters do not match (empirically verified), and `perl`
///   panics without it.
pub(super) const ALLOWED_SYSCTL_PREFIXES: &[&str] = &["sysctl.", "hw.pagesize"];
