//! The macOS `sandbox-exec` harness the platform tests share.

#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use super::super::{seatbelt_profile, SandboxSpec};

// ------------------------------------------------------------------
// Real `sandbox-exec` checks. Ignored by default because they run the
// platform sandbox; run them explicitly on macOS with
// `cargo test -p auxesis-kernel-mcp -- --ignored --nocapture`.
// ------------------------------------------------------------------

/// Run `program` under `profile`, returning its exit status and stderr.
#[cfg(target_os = "macos")]
pub(super) fn run_under(profile: &str, program: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .arg(program)
        .args(args)
        .output()
        .expect("run sandbox-exec")
}

/// Canonicalise a path the kernel will match against.
#[cfg(target_os = "macos")]
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().expect("canonical path")
}

/// A spec rooted in fresh temp dirs, with the given runtime paths.
#[cfg(target_os = "macos")]
pub(super) fn temp_spec_paths(
    runtime: Vec<PathBuf>,
    proxy_port: Option<u16>,
) -> (tempfile::TempDir, SandboxSpec) {
    let root = tempfile::tempdir().expect("install dir");
    let install = canonical(root.path());
    let work = install.join("work");
    std::fs::create_dir_all(&work).expect("work dir");
    let spec = SandboxSpec {
        install_dir: install,
        work_dir: work,
        runtime_read_paths: runtime,
        proxy_port,
    };
    (root, spec)
}

/// A spec rooted in fresh temp dirs, with the given exact interpreters.
#[cfg(target_os = "macos")]
pub(super) fn temp_spec(
    runtime: &[&str],
    proxy_port: Option<u16>,
) -> (tempfile::TempDir, SandboxSpec) {
    temp_spec_paths(runtime.iter().map(PathBuf::from).collect(), proxy_port)
}

/// A tiny C probe for the operations no stock CLI exposes: reading another
/// process's argv (`sysctl KERN_PROCARGS2`) and path (`proc_pidpath`),
/// `dlopen`, the IOKit platform serial, and a raw TCP/UDP connect. It
/// never prints the serial value, only whether the read succeeded.
#[cfg(target_os = "macos")]
const PROBE_C: &str = r##"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <dlfcn.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

static int fill(struct sockaddr_in *a, const char *host, const char *port) {
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port = htons((unsigned short)atoi(port));
    return inet_pton(AF_INET, host, &a->sin_addr) == 1 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("USAGE\n"); return 2; }
    if (!strcmp(argv[1], "args") && argc == 3) {
        int mib[3] = {CTL_KERN, KERN_PROCARGS2, atoi(argv[2])};
        size_t size = 0;
        if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0) { printf("ARGS_DENIED:%d\n", errno); return 0; }
        char *buf = malloc(size ? size : 1);
        if (sysctl(mib, 3, buf, &size, NULL, 0) != 0) { printf("ARGS_DENIED:%d\n", errno); free(buf); return 0; }
        printf("ARGS_OK\n"); free(buf); return 0;
    }
    if (!strcmp(argv[1], "path") && argc == 3) {
        char buf[4096];
        if (proc_pidpath(atoi(argv[2]), buf, sizeof(buf)) <= 0) { printf("PATH_DENIED:%d\n", errno); return 0; }
        printf("PATH_OK\n"); return 0;
    }
    if (!strcmp(argv[1], "dlopen") && argc == 3) {
        void *h = dlopen(argv[2], RTLD_NOW);
        if (!h) { printf("DLOPEN_FAIL\n"); return 0; }
        printf("DLOPEN_OK\n"); dlclose(h); return 0;
    }
    if (!strcmp(argv[1], "serial")) {
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
        if (!svc) { printf("SERIAL_DENIED:nomatch\n"); return 0; }
        CFTypeRef prop = IORegistryEntryCreateCFProperty(svc, CFSTR("IOPlatformSerialNumber"), kCFAllocatorDefault, 0);
        if (!prop) { printf("SERIAL_DENIED:noprop\n"); IOObjectRelease(svc); return 0; }
        CFRelease(prop); IOObjectRelease(svc); printf("SERIAL_OK\n"); return 0;
    }
    if (!strcmp(argv[1], "tcp") && argc == 4) {
        struct sockaddr_in a;
        if (fill(&a, argv[2], argv[3]) != 0) { printf("TCP_BADADDR\n"); return 0; }
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { printf("TCP_DENIED:%d\n", errno); return 0; }
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { printf("TCP_DENIED:%d\n", errno); close(fd); return 0; }
        printf("TCP_OK\n"); close(fd); return 0;
    }
    if (!strcmp(argv[1], "udp") && argc == 4) {
        struct sockaddr_in a;
        if (fill(&a, argv[2], argv[3]) != 0) { printf("UDP_BADADDR\n"); return 0; }
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { printf("UDP_DENIED:%d\n", errno); return 0; }
        if (sendto(fd, "x", 1, 0, (struct sockaddr *)&a, sizeof(a)) < 0) { printf("UDP_DENIED:%d\n", errno); close(fd); return 0; }
        printf("UDP_OK\n"); close(fd); return 0;
    }
    printf("UNKNOWN\n"); return 2;
}
"##;

/// Compile [`PROBE_C`] into the (executable) install dir and return its path.
#[cfg(target_os = "macos")]
pub(super) fn compile_probe(install_dir: &Path) -> PathBuf {
    let source = install_dir.join("probe.c");
    std::fs::write(&source, PROBE_C).expect("write probe.c");
    let binary = install_dir.join("probe");
    let status = std::process::Command::new("/usr/bin/cc")
        .arg("-O0")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .args(["-framework", "IOKit", "-framework", "CoreFoundation"])
        .status()
        .expect("run cc");
    assert!(status.success(), "cc could not build the probe helper");
    binary
}

/// A trivial dylib with no dependencies, for the `dlopen` test.
#[cfg(target_os = "macos")]
pub(super) fn compile_dylib(dir: &Path, name: &str) -> PathBuf {
    let source = dir.join("dylib.c");
    std::fs::write(&source, "int probe_symbol(void) { return 42; }\n").expect("write dylib.c");
    let dylib = dir.join(name);
    let status = std::process::Command::new("/usr/bin/cc")
        .args(["-dynamiclib", "-o"])
        .arg(&dylib)
        .arg(&source)
        .status()
        .expect("run cc");
    assert!(status.success(), "cc could not build the test dylib");
    dylib
}

/// The canonical node binary and the read paths it needs, if node is
/// installed. `None` skips the node positive control on a host without it.
#[cfg(target_os = "macos")]
fn node_runtime() -> Option<(PathBuf, Vec<PathBuf>)> {
    let node = ["/opt/homebrew/bin/node", "/usr/local/bin/node"]
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .and_then(|path| path.canonicalize().ok())?;
    let lib = node.parent()?.parent()?.join("lib");
    let mut runtime = vec![PathBuf::from("/usr/bin/true"), node.clone(), lib];
    for path in [
        "/opt/homebrew/opt",
        "/opt/homebrew/Cellar",
        "/opt/homebrew/lib",
        "/opt/homebrew/etc/openssl@3/openssl.cnf",
        "/opt/homebrew/etc/ca-certificates",
    ] {
        let path = PathBuf::from(path);
        if path.exists() {
            runtime.push(path);
        }
    }
    Some((node, runtime))
}

/// Positive control: the node runtime still starts under the tightened
/// profile. Skipped, not failed, when node is not installed.
#[cfg(target_os = "macos")]
pub(super) fn assert_node_starts() {
    let Some((node, runtime)) = node_runtime() else {
        eprintln!("node not installed; skipping the node positive control");
        return;
    };
    let (_root, spec) = temp_spec_paths(runtime, None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let out = run_under(
        &profile,
        node.to_str().expect("utf-8"),
        &["-e", "console.log('node ok')"],
    );
    assert!(
        out.status.success() && out.stdout == b"node ok\n",
        "node must still start: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Positive control for every denial test: `/usr/bin/true` exits 0 under
/// the profile, so a non-zero exit below means the sandbox denied it, not
/// that the profile cannot run anything at all.
#[cfg(target_os = "macos")]
pub(super) fn assert_true_runs(profile: &str) {
    let out = run_under(profile, "/usr/bin/true", &[]);
    assert!(
        out.status.success(),
        "positive control /usr/bin/true failed: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
