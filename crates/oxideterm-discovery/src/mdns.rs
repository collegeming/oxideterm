// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! mDNS browse for hosts that advertise SSH.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};

/// Service type hosts use to advertise SSH (`avahi`, Bonjour printers, NAS).
const SSH_SERVICE_TYPE: &str = "_ssh._tcp.local.";

/// One host advertised over mDNS.
#[derive(Clone, Debug)]
pub(crate) struct MdnsHost {
    pub(crate) ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) hostname: Option<String>,
}

/// Browses `_ssh._tcp` services for `window` and returns every address they
/// advertise.
///
/// mDNS is best effort: a network without multicast still supports saved
/// addresses and the subnet sweep, so a daemon that cannot start (or a browse
/// that fails) yields no candidates instead of failing the scan.
pub(crate) async fn browse_ssh_services(window: Duration) -> Vec<MdnsHost> {
    // The mdns-sd daemon is synchronous, so it runs on a blocking thread and
    // leaves the scan itself async.
    tokio::task::spawn_blocking(move || browse_blocking(window))
        .await
        .unwrap_or_default()
}

fn browse_blocking(window: Duration) -> Vec<MdnsHost> {
    let Ok(daemon) = ServiceDaemon::new() else {
        return Vec::new();
    };
    let hosts = match daemon.browse(SSH_SERVICE_TYPE) {
        Ok(receiver) => collect(&receiver, window),
        Err(_) => Vec::new(),
    };
    let _ = daemon.shutdown();
    hosts
}

fn collect(receiver: &mdns_sd::Receiver<ServiceEvent>, window: Duration) -> Vec<MdnsHost> {
    let deadline = Instant::now() + window;
    let mut hosts = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                let hostname = hostname_without_root(service.get_hostname());
                for address in service.get_addresses() {
                    hosts.push(MdnsHost {
                        ip: address.to_ip_addr(),
                        port: service.get_port(),
                        hostname: hostname.clone(),
                    });
                }
            }
            // Other events carry no address, and a disconnected daemon ends the
            // window early.
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    hosts
}

/// mDNS names are fully qualified, with a trailing dot no user recognises.
fn hostname_without_root(hostname: &str) -> Option<String> {
    let trimmed = hostname.trim_end_matches('.');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_qualified_mdns_name_loses_its_root_label() {
        assert_eq!(
            hostname_without_root("nas.local.").as_deref(),
            Some("nas.local")
        );
        assert_eq!(
            hostname_without_root("nas.local").as_deref(),
            Some("nas.local")
        );
        assert_eq!(hostname_without_root("."), None);
        assert_eq!(hostname_without_root(""), None);
    }
}
