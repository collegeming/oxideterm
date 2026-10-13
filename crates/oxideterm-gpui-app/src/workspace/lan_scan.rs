//! LAN scan of saved SSH connections whose host moved.
//!
//! The scan itself is read-only: it probes addresses without authenticating and
//! only reports what it found. Moving a saved connection always goes through the
//! store and the node router, so a scan cannot bypass the normal persistence or
//! runtime identity paths.

use super::*;
use oxideterm_discovery::{
    DiscoveryLimits, DiscoveryMatch, DiscoveryMatchStatus, DiscoveryReport, DiscoveryRequest,
    DiscoveryTarget, HostAddress,
};

mod render;

/// A startup scan waits for session restoration and the first frame, like the
/// automatic update check, so a network sweep never competes with window creation.
const LAN_AUTO_SCAN_DELAY: Duration = Duration::from_secs(4);

pub(in crate::workspace) enum LanScanPhase {
    Scanning,
    Ready(DiscoveryReport),
    Failed(String),
}

pub(in crate::workspace) struct LanScanState {
    pub(in crate::workspace) open: bool,
    pub(in crate::workspace) phase: LanScanPhase,
    /// `None` scans every saved connection, `Some(id)` only that one.
    pub(in crate::workspace) scope: Option<String>,
    pub(in crate::workspace) scope_label: Option<String>,
    /// Localized outcome of the last applied update, shown inside the dialog.
    pub(in crate::workspace) notice: Option<String>,
    pub(in crate::workspace) last_targets: Vec<DiscoveryTarget>,
    pub(in crate::workspace) task: Option<Task<()>>,
    pub(in crate::workspace) generation: u64,
}

impl Default for LanScanState {
    fn default() -> Self {
        Self {
            open: false,
            phase: LanScanPhase::Scanning,
            scope: None,
            scope_label: None,
            notice: None,
            last_targets: Vec::new(),
            task: None,
            generation: 0,
        }
    }
}

/// Localized label key for one match status.
pub(in crate::workspace) fn lan_scan_status_key(status: &DiscoveryMatchStatus) -> &'static str {
    match status {
        DiscoveryMatchStatus::AddressChanged { .. } => {
            "sessionManager.lan_scan.status_address_changed"
        }
        // A suggestion exists only because the connection has no recorded host
        // key of its own, which is the fact the user has to weigh.
        DiscoveryMatchStatus::Suggested { .. } => "sessionManager.lan_scan.status_no_fingerprint",
        DiscoveryMatchStatus::UpToDate { .. } => "sessionManager.lan_scan.status_up_to_date",
        DiscoveryMatchStatus::MultipleMatches { .. } => {
            "sessionManager.lan_scan.status_multiple_matches"
        }
        DiscoveryMatchStatus::NotFound => "sessionManager.lan_scan.status_not_found",
    }
}

/// Renders one address as `host:port`.
pub(in crate::workspace) fn lan_scan_host_address(address: &HostAddress) -> String {
    match address.ip {
        std::net::IpAddr::V4(ip) => format!("{ip}:{}", address.port),
        // IPv6 literals need brackets to stay unambiguous next to the port.
        ip @ std::net::IpAddr::V6(_) => format!("[{ip}]:{}", address.port),
    }
}

/// The store change one applicable match asks for.
///
/// Owned, because applying it mutates the store and the router while the report
/// is only borrowed from `LanScanState::phase`.
struct LanScanChange {
    connection_id: String,
    /// Fingerprint to record before the endpoint moves, or the identity of an
    /// address that is already correct.
    fingerprint: Option<String>,
    /// `None` when the saved address is already the one the scan found.
    address: Option<HostAddress>,
}

/// Runs one scan off the UI thread.
async fn lan_scan_report(
    runtime: &tokio::runtime::Runtime,
    targets: Vec<DiscoveryTarget>,
) -> Result<DiscoveryReport, String> {
    let request = DiscoveryRequest {
        targets,
        subnet_scan: true,
        limits: DiscoveryLimits::default(),
    };
    runtime
        .spawn(async move { oxideterm_discovery::discover(request).await })
        .await
        .map_err(|error| error.to_string())
}

impl WorkspaceApp {
    pub(in crate::workspace) fn start_lan_scan(
        &mut self,
        connection_id: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let targets = self.lan_scan_targets(connection_id.as_deref());
        let scope_label = connection_id
            .as_deref()
            .and_then(|id| targets.iter().find(|target| target.connection_id == id))
            .map(|target| target.label.clone());
        self.lan_scan.generation = self.lan_scan.generation.wrapping_add(1);
        let generation = self.lan_scan.generation;
        self.lan_scan.open = true;
        self.lan_scan.phase = LanScanPhase::Scanning;
        self.lan_scan.scope = connection_id;
        self.lan_scan.scope_label = scope_label;
        self.lan_scan.notice = None;
        self.lan_scan.last_targets = targets.clone();
        let runtime = self.forwarding_runtime.clone();
        // Replacing the task stops the GPUI side of a sweep that is still running,
        // and the generation check drops its late result. The detached network
        // work finishes on the shared runtime without touching this state.
        self.lan_scan.task = Some(cx.spawn(async move |this, cx| {
            let result = lan_scan_report(&runtime, targets).await;
            let _ = this.update(cx, |app, cx| {
                if app.lan_scan.generation != generation {
                    return;
                }
                app.lan_scan.phase = match result {
                    Ok(report) => LanScanPhase::Ready(report),
                    Err(error) => LanScanPhase::Failed(error),
                };
                cx.notify();
            });
        }));
        cx.notify();
    }

    pub(in crate::workspace) fn rescan_lan_scan(&mut self, cx: &mut Context<Self>) {
        let scope = self.lan_scan.scope.clone();
        self.start_lan_scan(scope, cx);
    }

    pub(in crate::workspace) fn close_lan_scan_dialog(&mut self, cx: &mut Context<Self>) {
        self.lan_scan.open = false;
        // Dropping the GPUI task stops its await; the sweep already handed to the
        // runtime finishes on its own and its result is discarded.
        self.lan_scan.task = None;
        cx.notify();
    }

    pub(in crate::workspace) fn lan_scan_match_applicable(&self, m: &DiscoveryMatch) -> bool {
        match &m.status {
            DiscoveryMatchStatus::AddressChanged { .. }
            | DiscoveryMatchStatus::Suggested { .. } => true,
            DiscoveryMatchStatus::UpToDate { fingerprint } => !self
                .connection_store
                .connection_host_key_fingerprints(&m.connection_id)
                .contains(fingerprint),
            DiscoveryMatchStatus::MultipleMatches { .. } | DiscoveryMatchStatus::NotFound => false,
        }
    }

    pub(in crate::workspace) fn lan_scan_applicable_match_count(&self) -> usize {
        let LanScanPhase::Ready(report) = &self.lan_scan.phase else {
            return 0;
        };
        report
            .matches
            .iter()
            .filter(|m| self.lan_scan_match_applicable(m))
            .count()
    }

    pub(in crate::workspace) fn apply_lan_scan_match(
        &mut self,
        connection_id: &str,
        cx: &mut Context<Self>,
    ) {
        let Some(change) = self.lan_scan_pending_change(connection_id) else {
            return;
        };
        let notice = match self.apply_lan_scan_change(&change, cx) {
            Ok(()) => self.i18n_with("sessionManager.lan_scan.applied", &[("count", "1".into())]),
            Err(error) => {
                self.i18n_with("sessionManager.lan_scan.apply_failed", &[("error", error)])
            }
        };
        self.lan_scan.notice = Some(notice);
        cx.notify();
    }

    pub(in crate::workspace) fn apply_all_lan_scan_matches(&mut self, cx: &mut Context<Self>) {
        let (applied, error) = self.apply_lan_scan_matches(false, cx);
        let notice = match error {
            // A partial update still has to tell the user that one connection
            // could not be saved; the report keeps the remaining rows visible.
            Some(error) => {
                self.i18n_with("sessionManager.lan_scan.apply_failed", &[("error", error)])
            }
            None => self.i18n_with(
                "sessionManager.lan_scan.applied",
                &[("count", applied.to_string())],
            ),
        };
        self.lan_scan.notice = Some(notice);
        cx.notify();
    }

    pub(in crate::workspace) fn start_lan_auto_scan(&mut self, cx: &mut Context<Self>) {
        if !self
            .settings_store
            .settings()
            .connection_scan
            .auto_scan_on_startup
        {
            return;
        }
        if self.lan_scan.task.is_some() {
            return;
        }
        let targets = self.lan_scan_targets(None);
        if targets.is_empty() {
            // Without a saved connection there is nothing to recognise, and a
            // startup sweep for no one would only generate traffic.
            return;
        }
        self.lan_scan.last_targets = targets.clone();
        // One generation guards both scans, so a user-triggered scan taken while
        // startup waits always supersedes the startup result.
        self.lan_scan.generation = self.lan_scan.generation.wrapping_add(1);
        let generation = self.lan_scan.generation;
        let runtime = self.forwarding_runtime.clone();
        self.lan_scan.task = Some(cx.spawn(async move |this, cx| {
            Timer::after(LAN_AUTO_SCAN_DELAY).await;
            let Ok(report) = lan_scan_report(&runtime, targets).await else {
                return;
            };
            let _ = this.update(cx, |app, cx| {
                if app.lan_scan.generation != generation {
                    return;
                }
                app.lan_scan.phase = LanScanPhase::Ready(report);
                // Only a recorded identity may move a connection without the
                // user reviewing the row: a `known_hosts` suggestion stays a
                // suggestion until the dialog is opened.
                let (applied, error) = app.apply_lan_scan_matches(true, cx);
                let status = match error {
                    Some(error) => Some(
                        app.i18n_with("sessionManager.lan_scan.apply_failed", &[("error", error)]),
                    ),
                    None if applied > 0 => Some(app.i18n_with(
                        "sessionManager.lan_scan.applied",
                        &[("count", applied.to_string())],
                    )),
                    // A scan that changed nothing stays silent: the user never
                    // asked for it, so it must not interrupt with a status line.
                    None => None,
                };
                let Some(status) = status else {
                    return;
                };
                app.session_manager.update(cx, |state, cx| {
                    state.set_status(Some(status), cx);
                });
            });
        }));
    }

    /// Saved connections one scan may recognise, with the fingerprints that
    /// identify them.
    fn lan_scan_targets(&self, connection_id: Option<&str>) -> Vec<DiscoveryTarget> {
        // `known_hosts` is read once per distinct saved address: connections
        // share hosts often enough that a per-connection read would re-parse the
        // same file for every entry.
        let mut trusted_fingerprints: HashMap<(String, u16), Vec<String>> = HashMap::new();
        self.connection_store
            .connection_infos()
            .into_iter()
            .filter(|info| connection_id.is_none_or(|id| id == info.id))
            .map(|info| {
                let trusted = trusted_fingerprints
                    .entry((info.host.clone(), info.port))
                    .or_insert_with(|| {
                        oxideterm_ssh::known_host_keys(&info.host, info.port)
                            .map(|keys| keys.into_iter().map(|key| key.fingerprint).collect())
                            .unwrap_or_default()
                    })
                    .clone();
                DiscoveryTarget {
                    recorded_fingerprints: self
                        .connection_store
                        .connection_host_key_fingerprints(&info.id)
                        .to_vec(),
                    connection_id: info.id.clone(),
                    label: info.name.clone(),
                    host: info.host.clone(),
                    port: info.port,
                    trusted_fingerprints: trusted,
                }
            })
            .collect()
    }

    /// The change one applicable match asks for, if the current report holds it.
    fn lan_scan_pending_change(&self, connection_id: &str) -> Option<LanScanChange> {
        let LanScanPhase::Ready(report) = &self.lan_scan.phase else {
            return None;
        };
        let m = report
            .matches
            .iter()
            .find(|m| m.connection_id == connection_id)?;
        if !self.lan_scan_match_applicable(m) {
            return None;
        }
        let address = m.discovered.as_ref().map(|host| host.address);
        match &m.status {
            DiscoveryMatchStatus::AddressChanged { .. } => Some(LanScanChange {
                connection_id: m.connection_id.clone(),
                fingerprint: None,
                address,
            }),
            DiscoveryMatchStatus::Suggested { fingerprint } => Some(LanScanChange {
                connection_id: m.connection_id.clone(),
                fingerprint: Some(fingerprint.clone()),
                address,
            }),
            // The address is already correct, so only the missing identity is
            // recorded: the connection keeps the key it just proved.
            DiscoveryMatchStatus::UpToDate { fingerprint } => Some(LanScanChange {
                connection_id: m.connection_id.clone(),
                fingerprint: Some(fingerprint.clone()),
                address: None,
            }),
            DiscoveryMatchStatus::MultipleMatches { .. } | DiscoveryMatchStatus::NotFound => None,
        }
    }

    /// Applies the changes of every applicable match of the current report.
    ///
    /// `address_changes_only` is used by the startup scan, which must not act on
    /// a `known_hosts` suggestion. Returns how many connections were updated
    /// together with the first error, so one unreachable store record cannot stop
    /// the remaining updates.
    fn apply_lan_scan_matches(
        &mut self,
        address_changes_only: bool,
        cx: &mut Context<Self>,
    ) -> (usize, Option<String>) {
        let connection_ids = self.lan_scan_applicable_ids(|status| {
            !address_changes_only || matches!(status, DiscoveryMatchStatus::AddressChanged { .. })
        });
        let mut applied = 0;
        let mut error = None;
        for connection_id in connection_ids {
            let Some(change) = self.lan_scan_pending_change(&connection_id) else {
                continue;
            };
            match self.apply_lan_scan_change(&change, cx) {
                Ok(()) => applied += 1,
                Err(message) => {
                    error.get_or_insert(message);
                }
            }
        }
        (applied, error)
    }

    /// Connection ids of the applicable matches, snapshotted so applying one
    /// change may borrow the store while the report is still in `self`.
    fn lan_scan_applicable_ids(
        &self,
        include: impl Fn(&DiscoveryMatchStatus) -> bool,
    ) -> Vec<String> {
        let LanScanPhase::Ready(report) = &self.lan_scan.phase else {
            return Vec::new();
        };
        report
            .matches
            .iter()
            .filter(|m| include(&m.status) && self.lan_scan_match_applicable(m))
            .map(|m| m.connection_id.clone())
            .collect()
    }

    fn apply_lan_scan_change(
        &mut self,
        change: &LanScanChange,
        cx: &mut Context<Self>,
    ) -> Result<(), String> {
        if let Some(fingerprint) = change.fingerprint.as_deref() {
            self.connection_store
                .record_connection_host_key_fingerprint(&change.connection_id, fingerprint)
                .map_err(|error| error.to_string())?;
        }
        let Some(address) = change.address else {
            return Ok(());
        };
        let host = address.ip.to_string();
        self.connection_store
            .update_connection_endpoint(&change.connection_id, &host, address.port)
            .map_err(|error| error.to_string())?;
        // The router owns the addresses runtime nodes connect to; the UI mirror
        // below is only its projection.
        self.node_router
            .retarget_saved_connection(&change.connection_id, &host, address.port);
        self.refresh_saved_connection_endpoint_nodes(&change.connection_id, cx);
        // The row that asked for this update now describes the old state, so the
        // dialog would keep offering the same update until the next scan.
        self.mark_lan_scan_match_applied(&change.connection_id);
        Ok(())
    }

    /// Rewrites one applied row to the state it just reached.
    ///
    /// Only an address change needs rewriting: a row whose address was already
    /// correct hides its action by itself once the identity is recorded.
    fn mark_lan_scan_match_applied(&mut self, connection_id: &str) {
        let LanScanPhase::Ready(report) = &mut self.lan_scan.phase else {
            return;
        };
        let Some(entry) = report
            .matches
            .iter_mut()
            .find(|entry| entry.connection_id == connection_id)
        else {
            return;
        };
        let fingerprint = match &entry.status {
            DiscoveryMatchStatus::AddressChanged { fingerprint }
            | DiscoveryMatchStatus::Suggested { fingerprint } => fingerprint.clone(),
            DiscoveryMatchStatus::UpToDate { .. }
            | DiscoveryMatchStatus::MultipleMatches { .. }
            | DiscoveryMatchStatus::NotFound => return,
        };
        entry.status = DiscoveryMatchStatus::UpToDate { fingerprint };
    }

    /// Re-reads the authoritative endpoint of every UI node owned by one saved
    /// connection.
    ///
    /// Proxy hops materialize the same saved connection id, so re-reading the
    /// router keeps their own addresses intact instead of moving them too.
    fn refresh_saved_connection_endpoint_nodes(
        &mut self,
        connection_id: &str,
        cx: &mut Context<Self>,
    ) {
        let mut reconnect = Vec::new();
        for (node_id, node) in self.ssh_nodes.iter_mut() {
            if node.saved_connection_id.as_deref() != Some(connection_id) {
                continue;
            }
            let Some(metadata) = self.node_router.node_metadata(node_id) else {
                continue;
            };
            node.endpoint.host = metadata.host;
            node.endpoint.port = metadata.port;
            if matches!(
                node.readiness,
                NodeReadiness::Error | NodeReadiness::Disconnected
            ) {
                reconnect.push(node_id.clone());
            }
        }
        // A transport that already failed still points at the old address, so its
        // reconnect has to be re-queued against the new one.
        for node_id in reconnect {
            self.workspace_runtime.update(cx, |runtime, cx| {
                runtime.queue_reconnect_root(node_id.clone(), cx);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{TestAppContext, VisualTestContext};
    use oxideterm_connections::{
        ConnectionX11ForwardingOptions, DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS, SaveConnectionRequest,
        SavedAuth, SavedUpstreamProxyPolicy, SshAlgorithmPreferences, SshChannelStrategy,
    };
    use oxideterm_discovery::{DiscoveredHost, DiscoverySource};

    /// Fingerprint the fixture connections recorded, which is what makes a scan
    /// match authoritative instead of a `known_hosts` suggestion.
    const FIXTURE_FINGERPRINT: &str = "SHA256:test-identity";
    const FIXTURE_NAME: &str = "Moved host";
    const FIXTURE_USERNAME: &str = "me";

    /// Re-runs the current test in a portable child process.
    ///
    /// Workspace storage is process-wide and applying a match persists the moved
    /// endpoint, so the fixture must not share the developer's connection store.
    /// Returns `None` in the parent process, which only reports the child result.
    fn portable_fixture(cx: &mut TestAppContext, fixture_key: &str) -> Option<PathBuf> {
        let executable = std::env::current_exe().unwrap();
        if let Some(fixture_dir) = std::env::var_os(fixture_key) {
            return Some(PathBuf::from(fixture_dir));
        }
        // Workspace storage is process-wide; a portable child keeps user data untouched.
        let directory = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let child = directory.path().join(executable.file_name().unwrap());
        fs::hard_link(&executable, &child).unwrap();
        fs::write(directory.path().join("portable"), []).unwrap();
        let output = std::process::Command::new(child)
            .arg(cx.test_function_name().unwrap())
            .arg("--nocapture")
            .env(fixture_key, directory.path())
            .env_remove("APPIMAGE")
            .current_dir(directory.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        None
    }

    fn quiet_startup_settings(fixture_dir: &Path) {
        let settings_path = default_settings_path();
        assert!(settings_path.starts_with(fixture_dir));
        let mut settings = SettingsStore::load_from_path(settings_path).unwrap();
        // The notice is asserted verbatim, and a headless test must neither read
        // the user's ssh config nor stop at the onboarding tour.
        settings.settings_mut().general.language = Language::En;
        settings.settings_mut().ssh_config.auto_load_hosts = false;
        settings.settings_mut().onboarding_completed = true;
        settings.save().unwrap();
    }

    fn with_workspace(
        cx: &mut TestAppContext,
        body: impl FnOnce(&mut VisualTestContext, Entity<WorkspaceApp>),
    ) {
        let (shell, cx) = cx.add_window_view(|window, cx| {
            let workspace = cx.new(|cx| WorkspaceApp::new(window, cx, None, None).unwrap());
            WorkspaceWindowShell::new(workspace, window, cx)
        });
        let workspace = shell.read_with(cx, |shell, _| shell.session_entity());
        body(cx, workspace);
    }

    fn host_address((host, port): (&str, u16)) -> HostAddress {
        HostAddress {
            ip: host.parse().unwrap(),
            port,
        }
    }

    fn connection_request(id: &str, name: &str, host: &str) -> SaveConnectionRequest {
        SaveConnectionRequest {
            totp_credential_id: None,
            id: Some(id.to_string()),
            name: name.to_string(),
            group: None,
            notes: None,
            host: host.to_string(),
            port: 22,
            username: FIXTURE_USERNAME.to_string(),
            auth: SavedAuth::Agent,
            proxy_chain: Vec::new(),
            upstream_proxy: SavedUpstreamProxyPolicy::UseGlobal,
            proxy_command: None,
            color: None,
            icon_background_color: None,
            icon: None,
            tags: Vec::new(),
            connect_timeout_seconds: DEFAULT_SSH_CONNECT_TIMEOUT_SECONDS,
            agent_forwarding: false,
            identity_agent: None,
            agent_forwarding_socket: None,
            legacy_ssh_compatibility: false,
            ssh_algorithms: SshAlgorithmPreferences::default(),
            x11_forwarding: ConnectionX11ForwardingOptions::default(),
            dedicated_new_terminal_connection: false,
            ssh_channel_strategy: SshChannelStrategy::default(),
            post_connect_command: None,
            terminal: ConnectionTerminalOptions::default(),
        }
    }

    /// Saves one SSH connection and records the identity a scan recognises it by.
    fn seed_connection(workspace: &mut WorkspaceApp, id: &str, name: &str, host: &str) {
        workspace
            .connection_store
            .upsert(connection_request(id, name, host))
            .unwrap();
        workspace
            .connection_store
            .record_connection_host_key_fingerprint(id, FIXTURE_FINGERPRINT)
            .unwrap();
    }

    /// One report row: a recorded identity found at a different address.
    fn address_changed_match(
        connection_id: &str,
        label: &str,
        previous: (&str, u16),
        discovered: (&str, u16),
    ) -> DiscoveryMatch {
        DiscoveryMatch {
            connection_id: connection_id.to_string(),
            label: label.to_string(),
            previous: host_address(previous),
            discovered: Some(DiscoveredHost {
                address: host_address(discovered),
                source: DiscoverySource::SubnetScan,
                hostname: Some("moved-host".to_string()),
                fingerprint: Some(FIXTURE_FINGERPRINT.to_string()),
                key_type: Some("ssh-ed25519".to_string()),
            }),
            status: DiscoveryMatchStatus::AddressChanged {
                fingerprint: FIXTURE_FINGERPRINT.to_string(),
            },
        }
    }

    #[gpui::test]
    fn applying_scan_match_moves_saved_connection_and_retires_report_row(cx: &mut TestAppContext) {
        let Some(fixture_dir) = portable_fixture(cx, "OXIDETERM_LAN_SCAN_APPLY_TEST_DIR") else {
            return;
        };
        quiet_startup_settings(&fixture_dir);
        let connection_id = "lan-scan-fixture";
        with_workspace(cx, |cx, workspace| {
            let created_at = workspace.update(cx, |workspace, _| {
                seed_connection(workspace, connection_id, FIXTURE_NAME, "10.0.0.5");
                workspace
                    .connection_store
                    .get(connection_id)
                    .unwrap()
                    .created_at
            });
            // The dialog state a finished scan leaves behind, injected so the
            // apply path runs without probing any address.
            workspace.update(cx, |workspace, cx| {
                workspace.lan_scan.open = true;
                workspace.lan_scan.scope = Some(connection_id.to_string());
                workspace.lan_scan.last_targets = vec![DiscoveryTarget {
                    connection_id: connection_id.to_string(),
                    label: FIXTURE_NAME.to_string(),
                    host: "10.0.0.5".to_string(),
                    port: 22,
                    recorded_fingerprints: vec![FIXTURE_FINGERPRINT.to_string()],
                    trusted_fingerprints: Vec::new(),
                }];
                workspace.lan_scan.phase = LanScanPhase::Ready(DiscoveryReport {
                    matches: vec![address_changed_match(
                        connection_id,
                        FIXTURE_NAME,
                        ("10.0.0.5", 22),
                        ("10.0.0.9", 2222),
                    )],
                    other_hosts: Vec::new(),
                });
                assert_eq!(workspace.lan_scan_applicable_match_count(), 1);
                workspace.apply_lan_scan_match(connection_id, cx);
            });

            workspace.read_with(cx, |workspace, _| {
                let connection = workspace.connection_store.get(connection_id).unwrap();
                assert_eq!(connection.host, "10.0.0.9");
                assert_eq!(connection.port, 2222);
                assert_eq!(connection.name, FIXTURE_NAME);
                assert_eq!(connection.username, FIXTURE_USERNAME);
                assert_eq!(
                    connection.created_at, created_at,
                    "a moved endpoint must update the saved record instead of creating one"
                );
                assert!(
                    workspace
                        .connection_store
                        .connection_host_key_fingerprints(connection_id)
                        .contains(&FIXTURE_FINGERPRINT.to_string()),
                    "a moved connection keeps the identity the scan recognised it by"
                );

                let LanScanPhase::Ready(report) = &workspace.lan_scan.phase else {
                    panic!("the applied report must stay in the dialog");
                };
                assert!(
                    matches!(
                        &report.matches[0].status,
                        DiscoveryMatchStatus::UpToDate { fingerprint } if fingerprint == FIXTURE_FINGERPRINT
                    ),
                    "an applied row must stop advertising the address it left behind: {:?}",
                    report.matches[0].status
                );
                assert_eq!(workspace.lan_scan_applicable_match_count(), 0);
                assert_eq!(
                    workspace.lan_scan.notice.as_deref(),
                    Some("Updated 1 saved connection(s)")
                );
            });

            // The move has to survive a restart, which only the file proves.
            let store_path = workspace.read_with(cx, |workspace, _| {
                workspace.connection_store.path().to_path_buf()
            });
            let reloaded = ConnectionStore::load(store_path).unwrap();
            let persisted = reloaded.get(connection_id).unwrap();
            assert_eq!(persisted.host, "10.0.0.9");
            assert_eq!(persisted.port, 2222);
        });
    }

    #[gpui::test]
    fn applying_all_scan_matches_moves_only_recognised_connections(cx: &mut TestAppContext) {
        let Some(fixture_dir) = portable_fixture(cx, "OXIDETERM_LAN_SCAN_APPLY_ALL_TEST_DIR")
        else {
            return;
        };
        quiet_startup_settings(&fixture_dir);
        with_workspace(cx, |cx, workspace| {
            workspace.update(cx, |workspace, cx| {
                seed_connection(workspace, "moved-connection", FIXTURE_NAME, "10.0.0.5");
                seed_connection(workspace, "absent-connection", "Absent host", "10.0.0.7");
                workspace.lan_scan.phase = LanScanPhase::Ready(DiscoveryReport {
                    matches: vec![
                        address_changed_match(
                            "moved-connection",
                            FIXTURE_NAME,
                            ("10.0.0.5", 22),
                            ("10.0.0.9", 2222),
                        ),
                        DiscoveryMatch {
                            connection_id: "absent-connection".to_string(),
                            label: "Absent host".to_string(),
                            previous: host_address(("10.0.0.7", 22)),
                            discovered: None,
                            status: DiscoveryMatchStatus::NotFound,
                        },
                    ],
                    other_hosts: Vec::new(),
                });
                workspace.apply_all_lan_scan_matches(cx);
            });

            workspace.read_with(cx, |workspace, _| {
                let moved = workspace.connection_store.get("moved-connection").unwrap();
                assert_eq!(moved.host, "10.0.0.9");
                assert_eq!(moved.port, 2222);
                // Nothing proved the absent address wrong, so the batch must
                // leave that connection where the user put it.
                let absent = workspace.connection_store.get("absent-connection").unwrap();
                assert_eq!(absent.host, "10.0.0.7");
                assert_eq!(absent.port, 22);
                assert_eq!(workspace.lan_scan_applicable_match_count(), 0);
                assert_eq!(
                    workspace.lan_scan.notice.as_deref(),
                    Some("Updated 1 saved connection(s)")
                );
            });
        });
    }
}
