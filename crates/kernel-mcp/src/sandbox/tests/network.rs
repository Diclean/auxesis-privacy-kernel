//! Network rules: no rule at all, one loopback port, one transport.

#[cfg(target_os = "macos")]
use super::super::seatbelt_profile;
#[cfg(target_os = "macos")]
use super::platform::{assert_true_runs, compile_probe, run_under, temp_spec};

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_denies_network() {
    // No proxy port: no network rule at all, so even loopback is denied.
    let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/nc"], None);
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let out = run_under(
        &profile,
        "/usr/bin/nc",
        &["-z", "-w", "2", "1.1.1.1", "443"],
    );
    assert!(
        !out.status.success(),
        "the sandbox must deny the outbound connection, got {:?}",
        out.status
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_allows_only_the_proxy_port_on_ipv4_loopback() {
    use std::net::TcpListener;

    // A listener on the allowed port, one on a *different* loopback port,
    // and one on IPv6 loopback. Keeping them open makes a refused connect
    // distinguishable from a sandbox denial only by the exit status; we
    // assert the denied cases fail even though something is listening.
    let allowed = TcpListener::bind(("127.0.0.1", 0)).expect("allowed listener");
    let allowed_port = allowed.local_addr().expect("addr").port();
    let other = TcpListener::bind(("127.0.0.1", 0)).expect("other listener");
    let other_port = other.local_addr().expect("addr").port();
    let v6 = TcpListener::bind(("::1", 0)).expect("v6 listener");
    let v6_port = v6.local_addr().expect("addr").port();
    for listener in [&allowed, &other, &v6] {
        listener.set_nonblocking(true).expect("nonblocking");
    }

    let (_root, spec) = temp_spec(&["/usr/bin/true", "/usr/bin/nc"], Some(allowed_port));
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);

    // Positive control: the allowed port connects.
    let out = run_under(
        &profile,
        "/usr/bin/nc",
        &["-z", "-w", "2", "127.0.0.1", &allowed_port.to_string()],
    );
    assert!(
        out.status.success(),
        "the proxy port must connect: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );

    // A different loopback port, IPv6 loopback and a public address are all
    // denied even though the first two have listeners.
    for (host, port) in [
        ("127.0.0.1", other_port.to_string()),
        ("::1", v6_port.to_string()),
        ("1.1.1.1", "443".to_string()),
    ] {
        let out = run_under(&profile, "/usr/bin/nc", &["-z", "-w", "2", host, &port]);
        assert!(
            !out.status.success(),
            "{host}:{port} must be denied, got {:?}",
            out.status
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the real macOS sandbox; run with --ignored"]
fn sandbox_allows_only_tcp_on_the_proxy_port() {
    use std::net::TcpListener;

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");

    let (_root, mut spec) = temp_spec(&["/usr/bin/true"], Some(port));
    let probe = compile_probe(&spec.install_dir);
    spec.runtime_read_paths.push(probe.clone());
    let profile = seatbelt_profile(&spec);
    assert_true_runs(&profile);
    let probe = probe.to_str().expect("utf-8");

    // TCP is the one allowed transport.
    let tcp = run_under(&profile, probe, &["tcp", "127.0.0.1", &port.to_string()]);
    assert!(
        tcp.status.success() && tcp.stdout == b"TCP_OK\n",
        "TCP to the proxy port must connect: {:?} {}",
        tcp.status,
        String::from_utf8_lossy(&tcp.stdout)
    );
    // UDP on the same port stays denied.
    let udp = run_under(&profile, probe, &["udp", "127.0.0.1", &port.to_string()]);
    assert!(
        udp.status.success() && String::from_utf8_lossy(&udp.stdout).starts_with("UDP_DENIED"),
        "UDP must be denied: {:?} {}",
        udp.status,
        String::from_utf8_lossy(&udp.stdout)
    );
}
