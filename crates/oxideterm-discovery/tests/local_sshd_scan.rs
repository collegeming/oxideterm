// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! End-to-end scan against a real `sshd` on a high port.
//!
//! Ignored by default: it needs `/usr/sbin/sshd`, `ssh-keygen`, `ssh-keyscan`,
//! a non-loopback IPv4 interface, and a spare high port. Run it with
//! `cargo test -p oxideterm-discovery --test local_sshd_scan -- --ignored --nocapture`.

use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr};
use oxideterm_discovery::{
    DiscoveryLimits, DiscoveryMatchStatus, DiscoveryRequest, DiscoverySource, DiscoveryTarget,
    HostAddress, discover,
};
use sha2::{Digest, Sha256};

const SSHD: &str = "/usr/sbin/sshd";

/// A test sshd holding one high port on one local address.
struct Sshd {
    child: Child,
    listen: Ipv4Addr,
    port: u16,
    temp: tempfile::TempDir,
}

impl Sshd {
    fn start(listen: Ipv4Addr, port: u16) -> Self {
        let temp = tempfile::tempdir().expect("a temp dir for the test sshd");
        let host_key = temp.path().join("host_ed25519");
        let keygen = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&host_key)
            .status()
            .expect("ssh-keygen runs");
        assert!(keygen.success(), "ssh-keygen could not create a host key");

        let config = temp.path().join("sshd_config");
        fs::write(
            &config,
            format!(
                "Port {port}\n\
                 ListenAddress {listen}\n\
                 HostKey {host_key}\n\
                 PidFile {pid_file}\n\
                 UsePAM no\n\
                 StrictModes no\n\
                 PasswordAuthentication no\n\
                 LogLevel ERROR\n",
                host_key = host_key.display(),
                pid_file = temp.path().join("sshd.pid").display(),
            ),
        )
        .expect("the sshd configuration is written");

        let log_path = temp.path().join("sshd.log");
        let log = fs::File::create(&log_path).expect("the sshd log file");
        // `-D` keeps sshd in the foreground so this test owns the daemon and can
        // always stop it again, unlike a daemon that detaches on startup.
        let child = Command::new(SSHD)
            .arg("-D")
            .arg("-f")
            .arg(&config)
            .arg("-E")
            .arg(&log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().expect("a second log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("sshd runs");

        let sshd = Self {
            child,
            listen,
            port,
            temp,
        };
        sshd.wait_until_listening();
        sshd
    }

    fn address(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.listen), self.port)
    }

    fn log(&self) -> String {
        fs::read_to_string(self.temp.path().join("sshd.log")).unwrap_or_default()
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&self.address(), Duration::from_millis(200)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "the test sshd never accepted a connection on {}; log:\n{}",
            self.address(),
            self.log()
        );
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // `-D` leaves no detached process behind, but a stale pid file is the
        // only handle left if sshd ever gets started differently.
        if let Ok(pid) = fs::read_to_string(self.temp.path().join("sshd.pid")) {
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(pid.trim())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[tokio::test]
#[ignore = "requires a local sshd on a high port"]
async fn a_moved_saved_connection_is_found_by_its_host_key() {
    let interface = local_ipv4_interface().expect(
        "this test needs an operational non-loopback IPv4 interface to listen on and sweep",
    );
    let port = free_port_on(interface.ip);
    assert_ne!(
        port, 2222,
        "2222 is occupied by another service on this host"
    );

    let sshd = Sshd::start(interface.ip, port);
    let expected = fingerprint_from_public_key(&sshd.temp.path().join("host_ed25519.pub"));
    // A second, independent opinion from OpenSSH itself, so a bug in the test's
    // own base64 digest cannot hide behind itself.
    assert_eq!(fingerprint_from_ssh_keyscan(interface.ip, port), expected);

    let dead = dead_address_in_subnet(&interface, port);
    println!(
        "sshd listening on {} with {expected}; saved connection points at {dead}:{port}",
        sshd.address()
    );

    let request = DiscoveryRequest {
        targets: vec![DiscoveryTarget {
            connection_id: "conn-moved".to_string(),
            label: "Moved host".to_string(),
            host: dead.to_string(),
            port,
            recorded_fingerprints: vec![expected.clone()],
            trusted_fingerprints: Vec::new(),
        }],
        subnet_scan: true,
        limits: DiscoveryLimits {
            probe_timeout_secs: 5,
            connect_timeout_ms: 400,
            // No mDNS responder is required for this scenario, so the browse
            // window only needs to be long enough to be a real browse.
            mdns_window_ms: 500,
            max_scan_hosts: 256,
        },
    };

    let report = discover(request).await;
    println!(
        "scan finished: {} match(es), {} other host(s)",
        report.matches.len(),
        report.other_hosts.len()
    );
    for host in &report.other_hosts {
        println!("  other host: {:?} {:?}", host.address, host.fingerprint);
    }

    assert_eq!(
        report.matches.len(),
        1,
        "one target must produce one match: {:?}",
        report.matches
    );
    let entry = &report.matches[0];
    assert_eq!(entry.connection_id, "conn-moved");
    assert_eq!(entry.previous.ip, IpAddr::V4(dead));
    match &entry.status {
        DiscoveryMatchStatus::AddressChanged { fingerprint } => assert_eq!(fingerprint, &expected),
        other => panic!(
            "the moved connection must be reported as an address change, got {other:?} ({:?})",
            report.matches
        ),
    }

    let found = entry
        .discovered
        .as_ref()
        .expect("a matched connection carries the discovered host");
    assert_eq!(
        found.address,
        HostAddress {
            ip: IpAddr::V4(interface.ip),
            port
        }
    );
    assert_eq!(found.fingerprint.as_deref(), Some(expected.as_str()));
    assert_eq!(found.key_type.as_deref(), Some("ssh-ed25519"));
    assert!(matches!(
        found.source,
        DiscoverySource::SubnetScan | DiscoverySource::Mdns
    ));
    assert!(
        !report
            .other_hosts
            .iter()
            .any(|host| host.address == found.address),
        "the matched host must not also be listed as an unrelated device"
    );
}

/// The interface this test listens on: an operational, non-loopback IPv4 address
/// on a subnet wide enough to hold neighbours, which is what a saved connection
/// must have moved away from. The sweep always covers this address, because a
/// scan that skipped the machine it runs on would miss it.
fn local_ipv4_interface() -> Option<Ifv4Addr> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|interface| match interface.addr {
            IfAddr::V4(address)
                if interface.oper_status == IfOperStatus::Up
                    && !address.ip.is_loopback()
                    && !address.ip.is_link_local()
                    && address.prefixlen <= 30 =>
            {
                Some(address)
            }
            _ => None,
        })
}

fn free_port_on(address: Ipv4Addr) -> u16 {
    let listener =
        TcpListener::bind((address, 0)).expect("a free port on the interface under test");
    listener.local_addr().expect("the bound address").port()
}

/// A neighbouring address in the same subnet that answers no TCP connection, so
/// the saved connection looks like a device that moved away.
fn dead_address_in_subnet(interface: &Ifv4Addr, port: u16) -> Ipv4Addr {
    let network = u32::from(interface.ip) & u32::from(interface.netmask);
    let broadcast = network | !u32::from(interface.netmask);
    let mut candidate = u32::from(interface.ip);
    for _ in 0..64 {
        candidate += 1;
        if candidate >= broadcast {
            candidate = network + 1;
        }
        if candidate == u32::from(interface.ip) {
            continue;
        }
        let dead = Ipv4Addr::from(candidate);
        let address = SocketAddr::new(IpAddr::V4(dead), port);
        if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_err() {
            return dead;
        }
    }
    panic!(
        "every neighbour of {} in its subnet accepts connections on port {port}",
        interface.ip
    );
}

/// OpenSSH fingerprints are the SHA-256 of the raw key blob, printed as unpadded
/// base64. Computed here from the generated `.pub` file, without the code under
/// test.
fn fingerprint_from_public_key(path: &Path) -> String {
    let content = fs::read_to_string(path).expect("the generated public key");
    let blob = content
        .split_whitespace()
        .nth(1)
        .expect("the base64 key blob in the public key file");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .expect("a valid base64 key blob");
    let digest = Sha256::digest(&raw);
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    )
}

/// The same fingerprint as reported by `ssh-keyscan` piped through
/// `ssh-keygen -lf -`.
fn fingerprint_from_ssh_keyscan(address: Ipv4Addr, port: u16) -> String {
    let scanned = Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), "-t", "ed25519"])
        .arg(address.to_string())
        .output()
        .expect("ssh-keyscan runs");
    assert!(
        scanned.status.success(),
        "ssh-keyscan failed: {}",
        String::from_utf8_lossy(&scanned.stderr)
    );

    let mut keygen = Command::new("ssh-keygen")
        .args(["-lf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("ssh-keygen runs");
    keygen
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&scanned.stdout)
        .expect("the scanned key reaches ssh-keygen");
    let printed = keygen.wait_with_output().expect("ssh-keygen output");
    let line = String::from_utf8(printed.stdout).expect("utf8 fingerprint output");
    line.split_whitespace()
        .nth(1)
        .expect("a fingerprint field in the ssh-keygen line")
        .to_string()
}
