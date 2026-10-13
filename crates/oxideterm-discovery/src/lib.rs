// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! Discovery of SSH hosts reachable from this machine.
//!
//! A saved connection stores an address, so a device that takes a new address
//! becomes unreachable even though its host key never changed. This crate
//! gathers candidate addresses from mDNS, from the saved addresses themselves,
//! and from a sweep of the local subnets; reads the host key every candidate
//! presents; and reports which saved connection each key belongs to. Callers
//! decide what to do with the result: nothing here authenticates, sends
//! credentials, or writes `known_hosts`.

mod matcher;
mod mdns;
mod probe;
mod subnet;

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// A saved connection as the scanner sees it: identity, current endpoint, and
/// the fingerprints it may be recognised by.
#[derive(Clone, Debug)]
pub struct DiscoveryTarget {
    pub connection_id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    /// Fingerprints recorded together with the connection. A match here is
    /// authoritative, because the connection itself vouched for the key.
    pub recorded_fingerprints: Vec<String>,
    /// Fingerprints `known_hosts` holds for the saved address. A match here only
    /// suggests a move: the same key may belong to a different saved address.
    pub trusted_fingerprints: Vec<String>,
}

/// Work limits of one scan.
///
/// Every field bounds either wall-clock time or the number of candidates,
/// because a scan runs against an unknown network and must always terminate.
#[derive(Clone, Copy, Debug)]
pub struct DiscoveryLimits {
    /// Budget for the SSH handshake of one candidate address, and for resolving
    /// one saved host name (a saved connection must not disappear from a report
    /// only because its resolver answered slowly).
    pub probe_timeout_secs: u64,
    /// Budget for one TCP connection attempt.
    pub connect_timeout_ms: u64,
    /// How long mDNS responses are collected before probing starts.
    pub mdns_window_ms: u64,
    /// Upper bound on swept host addresses, so an oversized subnet cannot turn a
    /// scan into an internet-wide one.
    pub max_scan_hosts: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            probe_timeout_secs: 5,
            connect_timeout_ms: 400,
            mdns_window_ms: 3000,
            max_scan_hosts: 1024,
        }
    }
}

/// One scan: the saved connections to match, and how much work it may do.
#[derive(Clone, Debug)]
pub struct DiscoveryRequest {
    pub targets: Vec<DiscoveryTarget>,
    /// Whether to sweep the local subnets in addition to mDNS and saved addresses.
    pub subnet_scan: bool,
    pub limits: DiscoveryLimits,
}

/// One address a scan can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostAddress {
    pub ip: IpAddr,
    pub port: u16,
}

/// Where a candidate address came from. The variants are declared in priority
/// order: when several sources report the same address, the earliest wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoverySource {
    Mdns,
    SubnetScan,
    SavedAddress,
}

/// A host that answered on a scanned address.
#[derive(Clone, Debug)]
pub struct DiscoveredHost {
    pub address: HostAddress,
    pub source: DiscoverySource,
    pub hostname: Option<String>,
    /// `None` when the address accepted TCP but no SSH host key could be read.
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
}

/// How a saved connection relates to what the scan found.
#[derive(Clone, Debug)]
pub enum DiscoveryMatchStatus {
    /// A recorded fingerprint was found at a different address.
    AddressChanged { fingerprint: String },
    /// A `known_hosts` fingerprint was found at a different address.
    Suggested { fingerprint: String },
    /// A known fingerprint is still served by the saved address.
    UpToDate { fingerprint: String },
    /// The same known fingerprint was found at several addresses, so the scan
    /// cannot say which one the connection moved to.
    MultipleMatches { candidates: Vec<HostAddress> },
    /// No known fingerprint was found anywhere on this network.
    NotFound,
}

/// One saved connection and what the scan found for it.
#[derive(Clone, Debug)]
pub struct DiscoveryMatch {
    pub connection_id: String,
    pub label: String,
    pub previous: HostAddress,
    /// The host behind `status` when the match is unambiguous.
    pub discovered: Option<DiscoveredHost>,
    pub status: DiscoveryMatchStatus,
}

/// Result of one scan.
#[derive(Clone, Debug)]
pub struct DiscoveryReport {
    pub matches: Vec<DiscoveryMatch>,
    /// Hosts that matched no saved connection.
    pub other_hosts: Vec<DiscoveredHost>,
}

/// A candidate address before probing, with the evidence that put it on the list.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub(crate) address: HostAddress,
    pub(crate) source: DiscoverySource,
    pub(crate) hostname: Option<String>,
}

/// Finds SSH hosts near this machine and matches them against saved connections.
///
/// Candidates are deduplicated by address, probed without authentication, and
/// reported per target. A target whose saved host cannot be resolved is absent
/// from `matches`: without an address there is nothing to compare a discovery
/// against.
pub async fn discover(request: DiscoveryRequest) -> DiscoveryReport {
    let DiscoveryRequest {
        targets,
        subnet_scan,
        limits,
    } = request;

    // Resolving first keeps the saved addresses available both as candidates and
    // as the "previous" address each match is reported against.
    let previous = resolve_saved_addresses(&targets, limits.probe_timeout_secs).await;

    let mut sources: Vec<(HostAddress, DiscoverySource, Option<String>)> = Vec::new();
    for host in mdns::browse_ssh_services(Duration::from_millis(limits.mdns_window_ms)).await {
        sources.push((
            HostAddress {
                ip: host.ip,
                port: host.port,
            },
            DiscoverySource::Mdns,
            host.hostname,
        ));
    }
    for (target, address) in targets.iter().zip(&previous) {
        let Some(address) = address else { continue };
        sources.push((
            *address,
            DiscoverySource::SavedAddress,
            saved_hostname(target),
        ));
    }
    if subnet_scan {
        let ports = sweep_ports(&targets);
        let subnets = subnet::local_ipv4_subnets();
        for host in subnet::swept_host_addresses(&subnets, limits.max_scan_hosts) {
            for port in &ports {
                sources.push((
                    HostAddress {
                        ip: IpAddr::V4(host),
                        port: *port,
                    },
                    DiscoverySource::SubnetScan,
                    None,
                ));
            }
        }
    }

    let discovered = probe::probe_candidates(merge_candidates(sources), limits).await;
    let resolved: Vec<(&DiscoveryTarget, HostAddress)> = targets
        .iter()
        .zip(&previous)
        .filter_map(|(target, address)| address.map(|address| (target, address)))
        .collect();
    matcher::build_report(&resolved, discovered)
}

async fn resolve_saved_addresses(
    targets: &[DiscoveryTarget],
    timeout_secs: u64,
) -> Vec<Option<HostAddress>> {
    let mut resolved = Vec::with_capacity(targets.len());
    for target in targets {
        resolved.push(resolve_saved_address(target, timeout_secs).await);
    }
    resolved
}

/// Resolves the saved endpoint of one target to an address the scan can compare
/// discoveries against.
///
/// Resolution shares the per-address probe budget: a network whose devices moved
/// can have a resolver that answers slowly or not at all, and a scan must not
/// hang on it.
async fn resolve_saved_address(target: &DiscoveryTarget, timeout_secs: u64) -> Option<HostAddress> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        return Some(HostAddress {
            ip,
            port: target.port,
        });
    }
    let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
    let timeout = Duration::from_secs(timeout_secs);
    let addresses: Vec<SocketAddr> = tokio::time::timeout(timeout, lookup)
        .await
        .ok()?
        .ok()?
        .collect();
    // IPv4 first: the subnet sweep only covers IPv4, so an IPv4 answer is the one
    // a discovery can meaningfully be compared with.
    let address = addresses
        .iter()
        .find(|address| address.is_ipv4())
        .or_else(|| addresses.first())?;
    Some(HostAddress {
        ip: address.ip(),
        port: target.port,
    })
}

/// The saved host text is worth keeping when it is a name rather than an
/// address: for a device that moves, the name is the only stable label.
fn saved_hostname(target: &DiscoveryTarget) -> Option<String> {
    target
        .host
        .parse::<IpAddr>()
        .is_err()
        .then(|| target.host.clone())
}

/// Ports the subnet sweep tries on every host: the SSH default plus every port a
/// saved connection uses, so a device that moved keeps its nonstandard port.
fn sweep_ports(targets: &[DiscoveryTarget]) -> Vec<u16> {
    let mut ports: BTreeSet<u16> = targets
        .iter()
        .map(|target| target.port)
        .filter(|port| *port != 0)
        .collect();
    ports.insert(22);
    ports.into_iter().collect()
}

/// Deduplicates candidate addresses, keeping the highest-priority source and the
/// best name known for each address.
fn merge_candidates(
    sources: impl IntoIterator<Item = (HostAddress, DiscoverySource, Option<String>)>,
) -> Vec<Candidate> {
    let mut merged: BTreeMap<(IpAddr, u16), Candidate> = BTreeMap::new();
    for (address, source, hostname) in sources {
        match merged.entry((address.ip, address.port)) {
            Entry::Occupied(mut entry) => {
                let candidate = entry.get_mut();
                if source_rank(source) < source_rank(candidate.source) {
                    candidate.source = source;
                    // A higher-priority source replaces the name even when it
                    // already has one: its name is the better evidence.
                    if hostname.is_some() {
                        candidate.hostname = hostname;
                    }
                } else if candidate.hostname.is_none() {
                    candidate.hostname = hostname;
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(Candidate {
                    address,
                    source,
                    hostname,
                });
            }
        }
    }
    merged.into_values().collect()
}

fn source_rank(source: DiscoverySource) -> u8 {
    match source {
        DiscoverySource::Mdns => 0,
        DiscoverySource::SubnetScan => 1,
        DiscoverySource::SavedAddress => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(ip: &str, port: u16) -> HostAddress {
        HostAddress {
            ip: ip.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn limits_default_to_the_documented_scan_budgets() {
        let limits = DiscoveryLimits::default();

        assert_eq!(limits.probe_timeout_secs, 5);
        assert_eq!(limits.connect_timeout_ms, 400);
        assert_eq!(limits.mdns_window_ms, 3000);
        assert_eq!(limits.max_scan_hosts, 1024);
    }

    #[test]
    fn merge_keeps_one_candidate_per_address_with_the_best_source_and_name() {
        let sources = vec![
            (
                address("10.0.0.5", 22),
                DiscoverySource::SavedAddress,
                Some("nas".to_string()),
            ),
            (address("10.0.0.5", 22), DiscoverySource::SubnetScan, None),
            (
                address("10.0.0.5", 22),
                DiscoverySource::Mdns,
                Some("nas.local".to_string()),
            ),
            (
                address("10.0.0.7", 2222),
                DiscoverySource::SavedAddress,
                Some("printer".to_string()),
            ),
            (address("10.0.0.9", 22), DiscoverySource::SubnetScan, None),
        ];

        let merged = merge_candidates(sources);

        assert_eq!(merged.len(), 3);
        let nas = &merged[0];
        assert_eq!(nas.address, address("10.0.0.5", 22));
        assert_eq!(nas.source, DiscoverySource::Mdns);
        assert_eq!(nas.hostname.as_deref(), Some("nas.local"));
        let printer = &merged[1];
        assert_eq!(printer.address, address("10.0.0.7", 2222));
        assert_eq!(printer.source, DiscoverySource::SavedAddress);
        assert_eq!(printer.hostname.as_deref(), Some("printer"));
        let swept = &merged[2];
        assert_eq!(swept.address, address("10.0.0.9", 22));
        assert_eq!(swept.source, DiscoverySource::SubnetScan);
        assert_eq!(swept.hostname, None);
    }

    #[test]
    fn merge_keeps_the_name_a_lower_priority_source_is_the_only_one_to_know() {
        let merged = merge_candidates(vec![
            (address("10.0.0.5", 22), DiscoverySource::Mdns, None),
            (
                address("10.0.0.5", 22),
                DiscoverySource::SavedAddress,
                Some("nas".to_string()),
            ),
        ]);

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].source, DiscoverySource::Mdns);
        assert_eq!(merged[0].hostname.as_deref(), Some("nas"));
    }

    #[test]
    fn merge_reports_the_same_address_once_even_for_identical_sources() {
        let merged = merge_candidates(vec![
            (address("10.0.0.5", 22), DiscoverySource::Mdns, None),
            (address("10.0.0.5", 22), DiscoverySource::Mdns, None),
        ]);

        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn sweep_ports_cover_the_ssh_default_and_every_saved_port() {
        let target = |port| DiscoveryTarget {
            connection_id: "id".to_string(),
            label: "label".to_string(),
            host: "10.0.0.5".to_string(),
            port,
            recorded_fingerprints: Vec::new(),
            trusted_fingerprints: Vec::new(),
        };

        assert_eq!(sweep_ports(&[]), vec![22]);
        assert_eq!(
            sweep_ports(&[target(2222), target(22), target(0)]),
            vec![22, 2222]
        );
    }

    #[test]
    fn saved_hostname_keeps_names_and_drops_addresses() {
        let mut target = DiscoveryTarget {
            connection_id: "id".to_string(),
            label: "label".to_string(),
            host: "nas.local".to_string(),
            port: 22,
            recorded_fingerprints: Vec::new(),
            trusted_fingerprints: Vec::new(),
        };

        assert_eq!(saved_hostname(&target).as_deref(), Some("nas.local"));
        target.host = "10.0.0.5".to_string();
        assert_eq!(saved_hostname(&target), None);
    }

    #[tokio::test]
    async fn saved_addresses_resolve_without_a_lookup() {
        let target = DiscoveryTarget {
            connection_id: "id".to_string(),
            label: "label".to_string(),
            host: "10.0.0.5".to_string(),
            port: 2222,
            recorded_fingerprints: Vec::new(),
            trusted_fingerprints: Vec::new(),
        };

        assert_eq!(
            resolve_saved_address(&target, 5).await,
            Some(address("10.0.0.5", 2222))
        );
    }
}
