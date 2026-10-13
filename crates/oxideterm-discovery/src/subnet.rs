// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! Local subnets and the host addresses a sweep visits.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use if_addrs::{IfAddr, IfOperStatus, get_if_addrs};

/// One IPv4 address of this machine together with the prefix length of the
/// subnet it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalSubnet {
    pub(crate) address: Ipv4Addr,
    pub(crate) prefix_len: u8,
}

/// IPv4 subnets this machine is attached to.
///
/// Loopback is left out (a /8 of loopback addresses would spend a whole sweep
/// budget on a single host) and so are interfaces without a carrier: a bridge
/// whose parent link is down, such as an unused docker0 or VM bridge, carries no
/// devices to find.
pub(crate) fn local_ipv4_subnets() -> Vec<LocalSubnet> {
    let Ok(interfaces) = get_if_addrs() else {
        return Vec::new();
    };
    let mut subnets: Vec<LocalSubnet> = interfaces
        .into_iter()
        .filter_map(|interface| {
            let IfAddr::V4(address) = interface.addr else {
                return None;
            };
            if address.ip.is_loopback() || interface.oper_status != IfOperStatus::Up {
                return None;
            }
            Some(LocalSubnet {
                address: address.ip,
                prefix_len: prefix_len(address.netmask),
            })
        })
        .collect();
    subnets.sort();
    subnets.dedup();
    subnets
}

/// Host addresses the sweep visits, at most `limit` of them.
///
/// The addresses of this machine are always included: probing ourselves is
/// legitimate (a service bound to a local address is worth finding), and on a
/// subnet larger than the budget the enumerated range may not reach the
/// interface address at all.
pub(crate) fn swept_host_addresses(subnets: &[LocalSubnet], limit: usize) -> Vec<Ipv4Addr> {
    let mut hosts: BTreeSet<Ipv4Addr> = subnets
        .iter()
        .map(|subnet| subnet.address)
        .filter(|address| !address.is_loopback())
        .collect();
    let mut budget = limit.saturating_sub(hosts.len());
    if budget == 0 || subnets.is_empty() {
        return hosts.into_iter().collect();
    }
    // Round robin across the subnets: a single large subnet must not spend the
    // whole budget while the subnet the machine actually uses goes unswept.
    let mut ranges: Vec<std::vec::IntoIter<Ipv4Addr>> = subnets
        .iter()
        .filter(|subnet| !subnet.address.is_loopback())
        .map(|subnet| enumerate_subnet_hosts(subnet.address, subnet.prefix_len, limit).into_iter())
        .collect();
    while budget > 0 {
        let mut exhausted = true;
        for range in ranges.iter_mut() {
            if budget == 0 {
                break;
            }
            // Hosts already in the set (the interface address of this subnet is
            // inserted up front) are skipped rather than counted, so a duplicate
            // does not consume this subnet's turn.
            for host in range.by_ref() {
                if hosts.insert(host) {
                    budget -= 1;
                    exhausted = false;
                    break;
                }
            }
        }
        if exhausted {
            break;
        }
    }
    hosts.into_iter().collect()
}

/// Usable host addresses of the subnet `address` sits on, in ascending order and
/// at most `limit` of them.
///
/// Network and broadcast addresses are skipped where the prefix leaves room for
/// them; `/31` and `/32` have no reserved pair (RFC 3021), so every address of
/// those subnets counts.
pub(crate) fn enumerate_subnet_hosts(
    address: Ipv4Addr,
    prefix_len: u8,
    limit: usize,
) -> Vec<Ipv4Addr> {
    if limit == 0 {
        return Vec::new();
    }
    let prefix_len = prefix_len.min(32);
    let total = 1u64 << (32 - u32::from(prefix_len));
    let (first_offset, usable) = if prefix_len >= 31 {
        (0, total)
    } else {
        (1, total - 2)
    };
    let count = usable.min(limit as u64);
    let base = u64::from(u32::from(address) & network_mask(prefix_len));
    let mut hosts = Vec::with_capacity(count as usize);
    for offset in 0..count {
        hosts.push(Ipv4Addr::from((base + first_offset + offset) as u32));
    }
    hosts
}

fn prefix_len(netmask: Ipv4Addr) -> u8 {
    u32::from(netmask).count_ones() as u8
}

fn network_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(address: &str, prefix_len: u8, limit: usize) -> Vec<String> {
        enumerate_subnet_hosts(address.parse().unwrap(), prefix_len, limit)
            .into_iter()
            .map(|host| host.to_string())
            .collect()
    }

    #[test]
    fn a_slash_24_holds_every_host_between_network_and_broadcast() {
        let enumerated = hosts("192.168.1.0", 24, 1000);

        assert_eq!(enumerated.len(), 254);
        assert_eq!(enumerated.first().map(String::as_str), Some("192.168.1.1"));
        assert_eq!(enumerated.last().map(String::as_str), Some("192.168.1.254"));
        assert!(!enumerated.iter().any(|host| host == "192.168.1.0"));
        assert!(!enumerated.iter().any(|host| host == "192.168.1.255"));
    }

    #[test]
    fn enumeration_starts_at_the_network_the_address_belongs_to() {
        // An interface address carries host bits; the subnet is what matters.
        assert_eq!(
            hosts("10.0.7.77", 24, 3),
            vec!["10.0.7.1", "10.0.7.2", "10.0.7.3"]
        );
    }

    #[test]
    fn enumeration_stops_at_the_limit() {
        assert_eq!(hosts("10.0.0.0", 24, 2), vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(hosts("10.0.0.0", 16, 2), vec!["10.0.0.1", "10.0.0.2"]);
        assert!(hosts("10.0.0.0", 24, 0).is_empty());
    }

    #[test]
    fn slash_31_and_slash_32_subnets_have_no_reserved_addresses() {
        assert_eq!(hosts("10.0.0.4", 31, 10), vec!["10.0.0.4", "10.0.0.5"]);
        assert_eq!(hosts("10.0.0.4", 32, 10), vec!["10.0.0.4"]);
    }

    #[test]
    fn the_sweep_includes_the_machine_itself_within_its_budget() {
        // 172.19.28.130 sits far past the first 8 addresses of its /20, so only
        // the explicit inclusion of interface addresses can put it in the sweep.
        let subnets = vec![LocalSubnet {
            address: "172.19.28.130".parse().unwrap(),
            prefix_len: 20,
        }];

        let swept = swept_host_addresses(&subnets, 8);

        assert_eq!(swept.len(), 8);
        assert!(swept.contains(&"172.19.28.130".parse::<Ipv4Addr>().unwrap()));
        assert!(swept.contains(&"172.19.16.1".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    fn the_sweep_shares_its_budget_between_subnets() {
        // The /24 interface address is deliberately not the first host of its
        // subnet, so both subnets can contribute a full share of the budget.
        let subnets = vec![
            LocalSubnet {
                address: "10.0.1.1".parse().unwrap(),
                prefix_len: 16,
            },
            LocalSubnet {
                address: "192.168.1.50".parse().unwrap(),
                prefix_len: 24,
            },
        ];

        let swept = swept_host_addresses(&subnets, 6);

        assert_eq!(swept.len(), 6);
        let from_second: Vec<Ipv4Addr> = swept
            .iter()
            .copied()
            .filter(|host| host.octets()[0] == 192)
            .collect();
        assert_eq!(
            from_second.len(),
            3,
            "a /16 must not consume the budget of a /24"
        );
    }

    #[test]
    fn the_sweep_always_covers_the_machine_itself_but_nothing_beyond_the_budget() {
        let subnets = vec![LocalSubnet {
            address: "10.0.1.1".parse().unwrap(),
            prefix_len: 24,
        }];
        let own_address = "10.0.1.1".parse::<Ipv4Addr>().unwrap();

        // A budget nothing else fits into still visits the machine's own
        // addresses: a scan that skips itself would miss a service bound to a
        // local address.
        assert_eq!(swept_host_addresses(&subnets, 1), vec![own_address]);
        assert_eq!(swept_host_addresses(&subnets, 0), vec![own_address]);
        assert!(swept_host_addresses(&[], 16).is_empty());
    }

    #[test]
    fn a_netmask_yields_the_prefix_length_it_represents() {
        assert_eq!(prefix_len("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(prefix_len("255.255.240.0".parse().unwrap()), 20);
        assert_eq!(prefix_len("255.255.255.255".parse().unwrap()), 32);
    }
}
