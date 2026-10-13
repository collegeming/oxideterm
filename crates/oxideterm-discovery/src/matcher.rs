// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! Matching of discovered hosts against saved connections.
//!
//! Matching is pure: it takes the addresses a scan reached and the fingerprints
//! of the connections to recognise, and decides for each connection what the
//! scan found. Keeping it separate from probing makes every status branch
//! testable without a network.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{
    DiscoveredHost, DiscoveryMatch, DiscoveryMatchStatus, DiscoveryReport, DiscoveryTarget,
    HostAddress,
};

/// Which fingerprint set produced a match. A fingerprint recorded with the
/// connection proves the identity, while a `known_hosts` entry for the saved
/// address only suggests it, so the two tiers produce different statuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FingerprintTier {
    Recorded,
    Trusted,
}

/// Builds the report for every target whose saved address could be resolved.
pub(crate) fn build_report(
    targets: &[(&DiscoveryTarget, HostAddress)],
    discovered: Vec<DiscoveredHost>,
) -> DiscoveryReport {
    let mut matches = Vec::with_capacity(targets.len());
    let mut consumed: BTreeSet<(IpAddr, u16)> = BTreeSet::new();
    for (target, previous) in targets {
        let (entry, used) = match_target(target, *previous, &discovered);
        consumed.extend(used);
        matches.push(entry);
    }
    // A host that belongs to a match is already described by that row; what
    // remains is the evidence of other devices on the network.
    let other_hosts = discovered
        .into_iter()
        .filter(|host| !consumed.contains(&(host.address.ip, host.address.port)))
        .collect();
    DiscoveryReport {
        matches,
        other_hosts,
    }
}

/// Matches one target and reports which addresses the match consumed.
fn match_target(
    target: &DiscoveryTarget,
    previous: HostAddress,
    discovered: &[DiscoveredHost],
) -> (DiscoveryMatch, Vec<(IpAddr, u16)>) {
    let recorded = hosts_with_fingerprint(discovered, &target.recorded_fingerprints);
    let (matched, tier) = if recorded.is_empty() {
        (
            hosts_with_fingerprint(discovered, &target.trusted_fingerprints),
            FingerprintTier::Trusted,
        )
    } else {
        (recorded, FingerprintTier::Recorded)
    };

    // Several services can share an address, so count distinct addresses rather
    // than probed hosts.
    let mut unique: BTreeMap<(IpAddr, u16), (&DiscoveredHost, &str)> = BTreeMap::new();
    for (host, fingerprint) in matched {
        unique
            .entry((host.address.ip, host.address.port))
            .or_insert((host, fingerprint));
    }

    let (discovered_host, status) = match unique.len() {
        0 => (None, DiscoveryMatchStatus::NotFound),
        1 => {
            let (&(ip, port), &(host, fingerprint)) = unique
                .iter()
                .next()
                .expect("the map holds exactly one entry");
            let address = HostAddress { ip, port };
            let fingerprint = fingerprint.to_string();
            let status = if address == previous {
                DiscoveryMatchStatus::UpToDate { fingerprint }
            } else if tier == FingerprintTier::Recorded {
                DiscoveryMatchStatus::AddressChanged { fingerprint }
            } else {
                DiscoveryMatchStatus::Suggested { fingerprint }
            };
            (Some(host.clone()), status)
        }
        _ => (
            None,
            DiscoveryMatchStatus::MultipleMatches {
                candidates: unique
                    .keys()
                    .map(|(ip, port)| HostAddress {
                        ip: *ip,
                        port: *port,
                    })
                    .collect(),
            },
        ),
    };

    let consumed = unique.keys().copied().collect();
    let entry = DiscoveryMatch {
        connection_id: target.connection_id.clone(),
        label: target.label.clone(),
        previous,
        discovered: discovered_host,
        status,
    };
    (entry, consumed)
}

/// Hosts whose fingerprint is one of `fingerprints`, with the matching value.
fn hosts_with_fingerprint<'a>(
    discovered: &'a [DiscoveredHost],
    fingerprints: &[String],
) -> Vec<(&'a DiscoveredHost, &'a str)> {
    discovered
        .iter()
        .filter_map(|host| {
            let fingerprint = host.fingerprint.as_deref()?;
            fingerprints
                .iter()
                .any(|known| known == fingerprint)
                .then_some((host, fingerprint))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDED: &str = "SHA256:recorded";
    const TRUSTED: &str = "SHA256:trusted";

    fn target(recorded: &[&str], trusted: &[&str]) -> DiscoveryTarget {
        DiscoveryTarget {
            connection_id: "conn-1".to_string(),
            label: "Saved".to_string(),
            host: "10.0.0.5".to_string(),
            port: 22,
            recorded_fingerprints: recorded.iter().map(|value| value.to_string()).collect(),
            trusted_fingerprints: trusted.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn saved() -> HostAddress {
        HostAddress {
            ip: "10.0.0.5".parse().unwrap(),
            port: 22,
        }
    }

    fn host(ip: &str, port: u16, fingerprint: Option<&str>) -> DiscoveredHost {
        DiscoveredHost {
            address: HostAddress {
                ip: ip.parse().unwrap(),
                port,
            },
            source: crate::DiscoverySource::SubnetScan,
            hostname: None,
            fingerprint: fingerprint.map(|value| value.to_string()),
            key_type: fingerprint.map(|_| "ssh-ed25519".to_string()),
        }
    }

    /// Renders a status so a test can name the branch and its payload in one
    /// assertion.
    fn status_text(entry: &DiscoveryMatch) -> String {
        match &entry.status {
            DiscoveryMatchStatus::AddressChanged { fingerprint } => {
                format!("address-changed {fingerprint}")
            }
            DiscoveryMatchStatus::Suggested { fingerprint } => format!("suggested {fingerprint}"),
            DiscoveryMatchStatus::UpToDate { fingerprint } => format!("up-to-date {fingerprint}"),
            DiscoveryMatchStatus::MultipleMatches { candidates } => {
                let addresses: Vec<String> = candidates
                    .iter()
                    .map(|address| format!("{}:{}", address.ip, address.port))
                    .collect();
                format!("multiple {}", addresses.join(","))
            }
            DiscoveryMatchStatus::NotFound => "not-found".to_string(),
        }
    }

    #[test]
    fn a_recorded_fingerprint_at_a_new_address_is_an_address_change() {
        let discovered = vec![host("10.0.0.9", 22, Some(RECORDED))];

        let (entry, consumed) =
            match_target(&target(&[RECORDED], &[TRUSTED]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("address-changed {RECORDED}"));
        assert_eq!(entry.previous, saved());
        assert_eq!(
            entry.discovered.map(|found| found.address),
            Some(HostAddress {
                ip: "10.0.0.9".parse().unwrap(),
                port: 22
            })
        );
        assert_eq!(consumed, vec![("10.0.0.9".parse().unwrap(), 22)]);
    }

    #[test]
    fn a_recorded_fingerprint_at_the_saved_address_is_up_to_date() {
        let discovered = vec![host("10.0.0.5", 22, Some(RECORDED))];

        let (entry, _) = match_target(&target(&[RECORDED], &[]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("up-to-date {RECORDED}"));
    }

    #[test]
    fn one_fingerprint_at_several_addresses_is_ambiguous() {
        // The saved address itself counts, so a device that answers on two
        // addresses cannot be pinned to one of them.
        let discovered = vec![
            host("10.0.0.5", 22, Some(RECORDED)),
            host("10.0.0.9", 2222, Some(RECORDED)),
        ];

        let (entry, consumed) = match_target(&target(&[RECORDED], &[]), saved(), &discovered);

        assert_eq!(status_text(&entry), "multiple 10.0.0.5:22,10.0.0.9:2222");
        assert_eq!(entry.discovered.is_none(), true);
        assert_eq!(consumed.len(), 2);
    }

    #[test]
    fn the_same_address_probed_twice_is_still_one_match() {
        let discovered = vec![
            host("10.0.0.9", 22, Some(RECORDED)),
            host("10.0.0.9", 22, Some(RECORDED)),
        ];

        let (entry, consumed) = match_target(&target(&[RECORDED], &[]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("address-changed {RECORDED}"));
        assert_eq!(consumed.len(), 1);
    }

    #[test]
    fn unknown_and_unreadable_fingerprints_are_not_found() {
        let discovered = vec![
            host("10.0.0.7", 22, Some("SHA256:someone-else")),
            // A host that answered TCP but never produced a key cannot prove
            // anything about a saved connection.
            host("10.0.0.8", 22, None),
        ];

        let (entry, consumed) =
            match_target(&target(&[RECORDED], &[TRUSTED]), saved(), &discovered);

        assert_eq!(status_text(&entry), "not-found");
        assert_eq!(entry.discovered.is_none(), true);
        assert!(consumed.is_empty());
    }

    #[test]
    fn a_trusted_fingerprint_at_a_new_address_is_only_suggested() {
        let discovered = vec![host("10.0.0.9", 22, Some(TRUSTED))];

        let (entry, _) = match_target(&target(&[RECORDED], &[TRUSTED]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("suggested {TRUSTED}"));
    }

    #[test]
    fn a_trusted_fingerprint_at_the_saved_address_is_up_to_date() {
        let discovered = vec![host("10.0.0.5", 22, Some(TRUSTED))];

        let (entry, _) = match_target(&target(&[], &[TRUSTED]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("up-to-date {TRUSTED}"));
    }

    #[test]
    fn recorded_fingerprints_take_precedence_over_trusted_ones() {
        // The trusted key still answers at the saved address, but the key the
        // connection itself recorded moved: that is the stronger evidence.
        let discovered = vec![
            host("10.0.0.5", 22, Some(TRUSTED)),
            host("10.0.0.9", 22, Some(RECORDED)),
        ];

        let (entry, _) = match_target(&target(&[RECORDED], &[TRUSTED]), saved(), &discovered);

        assert_eq!(status_text(&entry), format!("address-changed {RECORDED}"));
    }

    #[test]
    fn a_target_without_known_fingerprints_is_never_matched() {
        let discovered = vec![host("10.0.0.9", 22, Some(RECORDED))];

        let (entry, _) = match_target(&target(&[], &[]), saved(), &discovered);

        assert_eq!(status_text(&entry), "not-found");
    }

    #[test]
    fn build_report_keeps_only_unmatched_hosts_as_other_hosts() {
        let saved_target = target(&[RECORDED], &[]);
        let missing_target = DiscoveryTarget {
            connection_id: "conn-2".to_string(),
            ..target(&["SHA256:gone"], &[])
        };
        let unrelated = host("10.0.0.7", 22, Some("SHA256:someone-else"));
        let unreadable = host("10.0.0.8", 22, None);
        let discovered = vec![
            host("10.0.0.9", 22, Some(RECORDED)),
            unrelated.clone(),
            unreadable.clone(),
        ];

        let report = build_report(
            &[(&saved_target, saved()), (&missing_target, saved())],
            discovered,
        );

        assert_eq!(report.matches.len(), 2);
        assert_eq!(
            status_text(&report.matches[0]),
            format!("address-changed {RECORDED}")
        );
        assert_eq!(report.matches[0].label, "Saved");
        assert_eq!(report.matches[1].connection_id, "conn-2");
        assert_eq!(status_text(&report.matches[1]), "not-found");
        let other: Vec<HostAddress> = report.other_hosts.iter().map(|host| host.address).collect();
        assert_eq!(
            other,
            vec![unrelated.address, unreadable.address],
            "the matched address must not be reported as an unrelated device"
        );
    }
}
