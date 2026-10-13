// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! Probing of candidate addresses.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::{Candidate, DiscoveredHost, DiscoveryLimits};

/// Enough parallelism to sweep a /24 in seconds without exhausting file
/// descriptors or tripping SYN-flood protection on the way.
const PROBE_CONCURRENCY: usize = 32;

/// Probes every candidate and returns the addresses that carry a host.
///
/// Tasks live in a `JoinSet`, so dropping the scan (a cancelled scan in the UI)
/// aborts the probes instead of leaving them running in the background.
pub(crate) async fn probe_candidates(
    candidates: Vec<Candidate>,
    limits: DiscoveryLimits,
) -> Vec<DiscoveredHost> {
    let permits = Arc::new(Semaphore::new(PROBE_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let permits = Arc::clone(&permits);
        tasks.spawn(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return None;
            };
            probe_candidate(candidate, limits).await
        });
    }

    let mut discovered = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let Ok(Some(host)) = result else { continue };
        discovered.push(host);
    }
    // Task completion order is arbitrary; address order keeps a report stable
    // between runs.
    discovered.sort_by_key(|host| (host.address.ip, host.address.port));
    discovered
}

/// Probes one candidate address, or reports that nothing is there.
///
/// The TCP pre-check is what separates "nothing accepts connections here" from
/// "something accepts connections but is not SSH": only the latter is worth
/// reporting, and only with an unknown fingerprint, because a refused connection
/// says nothing about which device the address belongs to.
async fn probe_candidate(candidate: Candidate, limits: DiscoveryLimits) -> Option<DiscoveredHost> {
    let socket = SocketAddr::new(candidate.address.ip, candidate.address.port);
    let connect = TcpStream::connect(socket);
    let connect = tokio::time::timeout(Duration::from_millis(limits.connect_timeout_ms), connect);
    match connect.await {
        Ok(Ok(stream)) => drop(stream),
        // Refused, unroutable, or too slow to be part of this scan.
        _ => return None,
    }

    // The probe never authenticates: it stops as soon as the server has offered
    // its host key, so no credential is ever sent to an address found by a scan.
    let probe = oxideterm_ssh::probe_host_key_fingerprint(
        &candidate.address.ip.to_string(),
        candidate.address.port,
        limits.probe_timeout_secs,
    )
    .await;
    let (fingerprint, key_type) = match probe {
        Ok(probe) => (Some(probe.fingerprint), Some(probe.key_type)),
        Err(_) => (None, None),
    };

    Some(DiscoveredHost {
        address: candidate.address,
        source: candidate.source,
        hostname: candidate.hostname,
        fingerprint,
        key_type,
    })
}
