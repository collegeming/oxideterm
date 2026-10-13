//! Rendering of the LAN scan report dialog.
//!
//! The dialog only reports what a scan found: rows stay read-only until the user
//! applies one, and every action goes back through the `WorkspaceApp` methods
//! that own the store and router updates. The shell is the dismissible dialog
//! the ssh-config import uses, so a workspace-wide modal keeps one behaviour
//! whether it was opened from Settings or from the session manager.

use std::collections::BTreeSet;

use super::*;
use gpui::Div;
use oxideterm_discovery::{DiscoveryMatchStatus, DiscoveryReport, DiscoveryTarget};
use oxideterm_gpui_ui::button::{
    ButtonOptions, ButtonRadius, ButtonSize, ButtonVariant, ToolbarButtonOptions,
};
use oxideterm_gpui_ui::modal::{
    dialog_content, dialog_description, dialog_footer, dialog_header, dialog_title,
    dismissible_dialog_backdrop,
};
use oxideterm_gpui_ui::{MonospaceDatumOptions, MonospaceDatumTone};

/// One report row carries a connection name, two addresses, a status, and a
/// fingerprint, so it needs more width than the shared modal default.
const LAN_SCAN_DIALOG_WIDTH: f32 = 720.0;
const LAN_SCAN_DIALOG_MAX_HEIGHT_RATIO: f32 = 0.85;
/// Both ends of an address and of a fingerprint identify the value, so long ones
/// are middle-truncated instead of wrapping and breaking the row rhythm.
const LAN_SCAN_ADDRESS_MAX_CHARS: usize = 32;
const LAN_SCAN_FINGERPRINT_MAX_CHARS: usize = 48;
/// Stands in for a column the scan has no value for.
const LAN_SCAN_MISSING_VALUE: &str = "—";
/// Reads as "the saved address became the discovered one".
const LAN_SCAN_ADDRESS_ARROW: &str = "→";

/// One row of the report.
///
/// Owned and pre-formatted because a row outlives the borrow it was built from:
/// applying a row rewrites `LanScanState::phase` while the rows are rendered.
struct LanScanReportRow {
    /// `None` for a saved connection the scan could not resolve at all.
    connection_id: Option<String>,
    label: String,
    previous: String,
    discovered: String,
    discovered_tone: MonospaceDatumTone,
    status: String,
    status_color: u32,
    fingerprint: Option<String>,
    applicable: bool,
}

fn lan_scan_button_options(variant: ButtonVariant, disabled: bool) -> ToolbarButtonOptions {
    // Footer and row actions share the dialog Button contract: small, md radius,
    // and inert while disabled (the toolbar wrapper stops their activation).
    ToolbarButtonOptions {
        button: ButtonOptions {
            variant,
            size: ButtonSize::Sm,
            radius: ButtonRadius::Md,
            disabled,
        },
        ..ToolbarButtonOptions::default()
    }
}

/// The saved address of a target the scan never resolved.
///
/// Its address is a host string rather than a `HostAddress`, so only an IPv6
/// literal needs brackets to stay unambiguous next to the port.
fn lan_scan_saved_host_text(target: &DiscoveryTarget) -> String {
    let is_ipv6 = target
        .host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_ipv6());
    if is_ipv6 {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

/// The fingerprint a status was decided on, if the scan pinned one.
fn lan_scan_match_fingerprint(status: &DiscoveryMatchStatus) -> Option<String> {
    match status {
        DiscoveryMatchStatus::AddressChanged { fingerprint }
        | DiscoveryMatchStatus::Suggested { fingerprint }
        | DiscoveryMatchStatus::UpToDate { fingerprint } => Some(fingerprint.clone()),
        DiscoveryMatchStatus::MultipleMatches { .. } | DiscoveryMatchStatus::NotFound => None,
    }
}

fn lan_scan_discovered_tone(status: &DiscoveryMatchStatus) -> MonospaceDatumTone {
    match status {
        DiscoveryMatchStatus::AddressChanged { .. } => MonospaceDatumTone::Accent,
        // A suggestion rests on `known_hosts` alone, so it stays a warning until
        // the user accepts the new identity.
        DiscoveryMatchStatus::Suggested { .. } => MonospaceDatumTone::Warning,
        DiscoveryMatchStatus::UpToDate { .. }
        | DiscoveryMatchStatus::MultipleMatches { .. }
        | DiscoveryMatchStatus::NotFound => MonospaceDatumTone::Muted,
    }
}

impl WorkspaceApp {
    pub(in crate::workspace) fn render_lan_scan_dialog(
        &self,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        if !self.lan_scan.open {
            // The dialog state outlives its own rendering; a closed scan must not
            // leave a backdrop or an empty layer in the window.
            return div().into_any_element();
        }
        let theme = self.tokens.ui;
        // A scoped scan belongs to one saved connection, so the description has
        // to name it: the rows alone would not say which connection it was.
        let scoped_label = self
            .lan_scan
            .scope
            .as_ref()
            .and(self.lan_scan.scope_label.as_deref());
        let description = match scoped_label {
            Some(label) => format!(
                "{} · {label}",
                self.i18n.t("sessionManager.lan_scan.description")
            ),
            None => self.i18n.t("sessionManager.lan_scan.description"),
        };

        let mut body = div()
            .w_full()
            .min_w(px(0.0))
            .px(px(self.tokens.metrics.modal_body_padding))
            .py(px(self.tokens.metrics.modal_body_gap))
            .flex()
            .flex_col()
            .gap(px(self.tokens.metrics.modal_body_gap));
        if let Some(notice) = self.lan_scan.notice.clone() {
            // Applying a row leaves the report on screen, so the outcome is a
            // status line inside the dialog rather than a transient toast.
            body = body.child(self.connection_status_row(notice));
        }
        let body = match &self.lan_scan.phase {
            LanScanPhase::Scanning => body.child(self.render_lan_scan_scanning_state()),
            LanScanPhase::Failed(error) => body.child(oxideterm_gpui_ui::state_notice(
                &self.tokens,
                oxideterm_gpui_ui::UiStateTone::Error,
                Self::render_lucide_icon(LucideIcon::AlertTriangle, 16.0, rgb(theme.error)),
                self.i18n_with(
                    "sessionManager.lan_scan.failed",
                    &[("error", error.clone())],
                ),
                None,
            )),
            LanScanPhase::Ready(report) => self.render_lan_scan_report_body(body, report, cx),
        };
        // The scroll container is stateful, so it is built last: every branch
        // above only adds content to a plain column.
        let body = body
            .id("lan-scan-dialog-scroll")
            .flex_1()
            .min_h(px(0.0))
            .selectable_overflow_y_scroll(
                &self.selectable_text_scroll_handle("lan-scan-dialog-scroll"),
            );

        let applicable_count = self.lan_scan_applicable_match_count();
        let form = dialog_content(&self.tokens)
            .w(px(LAN_SCAN_DIALOG_WIDTH))
            .max_w(relative(0.92))
            .max_h(relative(LAN_SCAN_DIALOG_MAX_HEIGHT_RATIO))
            .flex()
            .flex_col()
            .shadow_lg()
            .on_mouse_down(MouseButton::Left, |_event, _window, cx| {
                cx.stop_propagation();
            })
            .child(
                dialog_header(&self.tokens)
                    .child(dialog_title(
                        &self.tokens,
                        self.i18n.t("sessionManager.lan_scan.title"),
                    ))
                    .child(dialog_description(&self.tokens, description)),
            )
            .child(body)
            .child(
                dialog_footer(&self.tokens)
                    .child(self.workspace_toolbar_action_button(
                        self.i18n.t("sessionManager.lan_scan.rescan"),
                        None,
                        lan_scan_button_options(ButtonVariant::Secondary, false),
                        cx.listener(|this, _event, _window, cx| {
                            this.rescan_lan_scan(cx);
                            cx.stop_propagation();
                        }),
                    ))
                    .child(self.workspace_toolbar_action_button(
                        self.i18n_with(
                            "sessionManager.lan_scan.apply",
                            &[("count", applicable_count.to_string())],
                        ),
                        None,
                        lan_scan_button_options(ButtonVariant::Default, applicable_count == 0),
                        cx.listener(|this, _event, _window, cx| {
                            this.apply_all_lan_scan_matches(cx);
                            cx.stop_propagation();
                        }),
                    ))
                    .child(self.workspace_toolbar_action_button(
                        self.i18n.t("sessionManager.lan_scan.close"),
                        None,
                        lan_scan_button_options(ButtonVariant::Secondary, false),
                        cx.listener(|this, _event, _window, cx| {
                            this.close_lan_scan_dialog(cx);
                            cx.stop_propagation();
                        }),
                    )),
            );

        dismissible_dialog_backdrop()
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _event, _window, cx| {
                    this.close_lan_scan_dialog(cx);
                    cx.stop_propagation();
                }),
            )
            .child(oxideterm_gpui_ui::motion::form_transition(
                &self.tokens,
                "lan-scan-dialog-transition",
                form,
                true,
            ))
            .into_any_element()
    }

    fn render_lan_scan_scanning_state(&self) -> AnyElement {
        let theme = self.tokens.ui;
        div()
            .w_full()
            .min_w(px(0.0))
            .py(px(self.tokens.metrics.modal_body_gap * 2.0))
            .flex()
            .flex_col()
            .items_center()
            .gap(px(self.tokens.spacing.three))
            .child(self.render_loading_icon("lan-scan-dialog-spinner", 20.0, rgb(theme.accent)))
            .child(
                div()
                    .text_size(px(self.tokens.metrics.ui_text_sm))
                    .text_color(rgb(theme.text_muted))
                    .child(self.i18n.t("sessionManager.lan_scan.scanning")),
            )
            .into_any_element()
    }

    fn render_lan_scan_empty_state(&self) -> AnyElement {
        let theme = self.tokens.ui;
        div()
            .w_full()
            .min_w(px(0.0))
            .rounded(px(self.tokens.radii.md))
            .border_1()
            .border_color(rgb(theme.border))
            .bg(rgb(theme.bg_panel))
            .px(px(self.tokens.spacing.three * 2.0))
            .py(px(self.tokens.spacing.three * 2.0))
            .flex()
            .flex_col()
            .items_center()
            .gap(px(6.0))
            .child(Self::render_lucide_icon(
                LucideIcon::WifiOff,
                20.0,
                rgb(theme.text_muted),
            ))
            .child(
                div()
                    .text_size(px(self.tokens.metrics.ui_text_sm))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(rgb(theme.text_heading))
                    .child(self.i18n.t("sessionManager.lan_scan.empty")),
            )
            .child(
                div()
                    .text_align(gpui::TextAlign::Center)
                    .text_size(px(self.tokens.metrics.ui_text_xs))
                    .text_color(rgb(theme.text_muted))
                    .child(self.i18n.t("sessionManager.lan_scan.empty_hint")),
            )
            .into_any_element()
    }

    fn render_lan_scan_report_body(
        &self,
        body: Div,
        report: &DiscoveryReport,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = self.tokens.ui;
        let rows = self.lan_scan_report_rows(report);
        let any_discovered_host =
            !report.other_hosts.is_empty() || report.matches.iter().any(|m| m.discovered.is_some());
        if !any_discovered_host {
            // Nothing answered on this network, so every row below can only say
            // "not found"; the empty state carries that message instead of a
            // summary that would repeat it.
            let body = body.child(self.render_lan_scan_empty_state());
            return if rows.is_empty() {
                body
            } else {
                body.child(self.render_lan_scan_rows(&rows, cx))
            };
        }

        let scoped = self.lan_scan.scope.as_deref();
        let mut discovered_addresses: BTreeSet<String> = BTreeSet::new();
        let mut matched = 0usize;
        for m in report
            .matches
            .iter()
            .filter(|m| scoped.is_none_or(|id| id == m.connection_id))
        {
            if let Some(host) = m.discovered.as_ref() {
                discovered_addresses.insert(lan_scan_host_address(&host.address));
            }
            if matches!(
                m.status,
                DiscoveryMatchStatus::AddressChanged { .. }
                    | DiscoveryMatchStatus::Suggested { .. }
            ) {
                matched += 1;
            }
        }
        // One device counts once even when several saved connections point at it.
        let hosts_found = report.other_hosts.len() + discovered_addresses.len();

        let mut body = body.child(
            div()
                .text_size(px(self.tokens.metrics.ui_text_sm))
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(rgb(theme.text))
                .child(self.i18n_with(
                    "sessionManager.lan_scan.summary",
                    &[
                        ("hosts", hosts_found.to_string()),
                        ("matches", matched.to_string()),
                    ],
                )),
        );
        if !rows.iter().any(|row| row.connection_id.is_some()) {
            // Other devices answered but none belongs to a saved connection.
            body = body.child(
                div()
                    .text_size(px(self.tokens.metrics.ui_text_sm))
                    .text_color(rgb(theme.text_muted))
                    .child(self.i18n.t("sessionManager.lan_scan.no_matches")),
            );
        }
        if !rows.is_empty() {
            // A scan with no saved connection (or none in scope) has no rows:
            // skip the table instead of rendering an empty one.
            body = body.child(self.render_lan_scan_rows(&rows, cx));
        }
        if !report.other_hosts.is_empty() {
            body = body.child(self.render_lan_scan_other_hosts(report));
        }
        body
    }

    fn render_lan_scan_rows(&self, rows: &[LanScanReportRow], cx: &mut Context<Self>) -> Div {
        let theme = self.tokens.ui;
        let mut table = div()
            .w_full()
            .min_w(px(0.0))
            .rounded(px(self.tokens.radii.md))
            .border_1()
            .border_color(rgb(theme.border))
            // A report can be long: the panel bounds the rows so the table keeps
            // the same surface while the dialog body scrolls it.
            .bg(rgb(theme.bg_panel))
            .p(px(8.0))
            .flex()
            .flex_col()
            .gap(px(2.0))
            .child(self.render_lan_scan_column_header());
        for row in rows {
            table = table.child(self.render_lan_scan_report_row(row, cx));
        }
        table
    }

    /// Column captions mirror the two lines of a row: identity above, evidence
    /// below, so the labels line up with the values they describe.
    fn render_lan_scan_column_header(&self) -> AnyElement {
        let theme = self.tokens.ui;
        let caption = |text: String| {
            div()
                .text_size(px(self.tokens.metrics.ui_text_xs))
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(rgb(theme.text_muted))
                .child(text)
        };
        div()
            .w_full()
            .min_w(px(0.0))
            .px(px(10.0))
            .pb(px(6.0))
            .flex()
            .flex_col()
            .gap(px(2.0))
            .border_b_1()
            .border_color(rgba((theme.border << 8) | 0x66))
            .child(
                div()
                    .min_w(px(0.0))
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(12.0))
                    .child(
                        caption(self.i18n.t("sessionManager.lan_scan.column_connection"))
                            .min_w(px(0.0))
                            .flex_1(),
                    )
                    .child(caption(
                        self.i18n.t("sessionManager.lan_scan.column_status"),
                    )),
            )
            .child(
                div()
                    .min_w(px(0.0))
                    .flex()
                    .flex_row()
                    .items_center()
                    .gap(px(6.0))
                    .child(caption(
                        self.i18n
                            .t("sessionManager.lan_scan.column_current_address"),
                    ))
                    .child(caption(LAN_SCAN_ADDRESS_ARROW.to_string()))
                    .child(caption(
                        self.i18n
                            .t("sessionManager.lan_scan.column_discovered_address"),
                    ))
                    .child(
                        caption(self.i18n.t("sessionManager.lan_scan.column_fingerprint"))
                            .min_w(px(0.0))
                            .flex_1(),
                    ),
            )
            .into_any_element()
    }

    fn render_lan_scan_report_row(
        &self,
        row: &LanScanReportRow,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let theme = self.tokens.ui;
        let mut evidence = div()
            .min_w(px(0.0))
            .flex()
            .flex_row()
            .items_center()
            .gap(px(6.0))
            .child(self.lan_scan_datum(
                &row.previous,
                MonospaceDatumTone::Muted,
                Some(LAN_SCAN_ADDRESS_MAX_CHARS),
            ))
            .child(
                div()
                    .flex_none()
                    .text_size(px(self.tokens.metrics.ui_text_xs))
                    .text_color(rgb(theme.text_muted))
                    .child(LAN_SCAN_ADDRESS_ARROW),
            )
            .child(self.lan_scan_datum(
                &row.discovered,
                row.discovered_tone,
                Some(LAN_SCAN_ADDRESS_MAX_CHARS),
            ));
        if let Some(fingerprint) = row.fingerprint.as_deref() {
            // The fingerprint takes the remaining width and truncates there, so a
            // long key cannot push the addresses out of the row.
            evidence = evidence.child(
                self.lan_scan_datum(
                    fingerprint,
                    MonospaceDatumTone::Muted,
                    Some(LAN_SCAN_FINGERPRINT_MAX_CHARS),
                )
                .min_w(px(0.0))
                .flex_1(),
            );
        }

        let apply_button =
            row.connection_id
                .as_ref()
                .filter(|_| row.applicable)
                .map(|connection_id| {
                    let connection_id = connection_id.clone();
                    self.workspace_toolbar_action_button(
                        self.i18n_with("sessionManager.lan_scan.apply", &[("count", "1".into())]),
                        None,
                        lan_scan_button_options(ButtonVariant::Default, false),
                        cx.listener(move |this, _event, _window, cx| {
                            this.apply_lan_scan_match(&connection_id, cx);
                            cx.stop_propagation();
                        }),
                    )
                });

        div()
            .w_full()
            .min_w(px(0.0))
            .px(px(10.0))
            .py(px(8.0))
            .flex()
            .flex_row()
            .items_center()
            .gap(px(12.0))
            .child(
                div()
                    .min_w(px(0.0))
                    .flex_1()
                    .flex()
                    .flex_col()
                    .gap(px(2.0))
                    .child(
                        div()
                            .truncate()
                            .text_size(px(self.tokens.metrics.ui_text_sm))
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .text_color(rgb(theme.text))
                            .child(row.label.clone()),
                    )
                    .child(evidence),
            )
            .child(
                div()
                    .flex_none()
                    .text_size(px(self.tokens.metrics.ui_text_xs))
                    .text_color(rgb(row.status_color))
                    .child(row.status.clone()),
            )
            .when_some(apply_button, |row_element, button| {
                row_element.child(button)
            })
            .into_any_element()
    }

    fn render_lan_scan_other_hosts(&self, report: &DiscoveryReport) -> AnyElement {
        let theme = self.tokens.ui;
        let mut section = div()
            .w_full()
            .min_w(px(0.0))
            .flex()
            .flex_col()
            .gap(px(6.0))
            .child(
                div()
                    .text_size(px(self.tokens.metrics.ui_text_sm))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(rgb(theme.text_heading))
                    .child(self.i18n.t("sessionManager.lan_scan.other_hosts_title")),
            )
            .child(
                div()
                    .text_size(px(self.tokens.metrics.ui_text_xs))
                    .text_color(rgb(theme.text_muted))
                    .child(self.i18n.t("sessionManager.lan_scan.other_hosts_hint")),
            );
        for host in &report.other_hosts {
            let mut row = div()
                .w_full()
                .min_w(px(0.0))
                .flex()
                .flex_row()
                .items_center()
                .gap(px(8.0))
                .child(
                    div()
                        .flex_none()
                        .text_size(px(self.tokens.metrics.ui_text_xs))
                        .text_color(rgb(theme.text_muted))
                        .child(self.i18n.t("sessionManager.lan_scan.other_hosts_address")),
                )
                .child(self.lan_scan_datum(
                    &lan_scan_host_address(&host.address),
                    MonospaceDatumTone::Primary,
                    Some(LAN_SCAN_ADDRESS_MAX_CHARS),
                ));
            if let Some(hostname) = host.hostname.as_deref() {
                row = row.child(
                    div()
                        .truncate()
                        .min_w(px(0.0))
                        .text_size(px(self.tokens.metrics.ui_text_xs))
                        .text_color(rgb(theme.text_muted))
                        .child(hostname.to_string()),
                );
            }
            if let Some(fingerprint) = host.fingerprint.as_deref() {
                row = row.child(
                    self.lan_scan_datum(
                        fingerprint,
                        MonospaceDatumTone::Muted,
                        Some(LAN_SCAN_FINGERPRINT_MAX_CHARS),
                    )
                    .min_w(px(0.0))
                    .flex_1(),
                );
            }
            section = section.child(row);
        }
        section.into_any_element()
    }

    fn lan_scan_report_rows(&self, report: &DiscoveryReport) -> Vec<LanScanReportRow> {
        let scoped = self.lan_scan.scope.as_deref();
        let mut rows = Vec::with_capacity(self.lan_scan.last_targets.len());
        for target in &self.lan_scan.last_targets {
            if scoped.is_some_and(|id| id != target.connection_id) {
                continue;
            }
            let Some(m) = report
                .matches
                .iter()
                .find(|m| m.connection_id == target.connection_id)
            else {
                // The engine omits a target whose saved address never resolved,
                // so the dialog still has to report that connection as not found.
                rows.push(LanScanReportRow {
                    connection_id: None,
                    label: target.label.clone(),
                    previous: lan_scan_saved_host_text(target),
                    discovered: LAN_SCAN_MISSING_VALUE.to_string(),
                    discovered_tone: MonospaceDatumTone::Muted,
                    status: self
                        .i18n
                        .t(lan_scan_status_key(&DiscoveryMatchStatus::NotFound)),
                    status_color: self.tokens.ui.text_muted,
                    // The saved key is the only identity such a connection has.
                    fingerprint: target.recorded_fingerprints.first().cloned(),
                    applicable: false,
                });
                continue;
            };
            rows.push(LanScanReportRow {
                connection_id: Some(m.connection_id.clone()),
                label: m.label.clone(),
                previous: lan_scan_host_address(&m.previous),
                discovered: m
                    .discovered
                    .as_ref()
                    .map(|host| lan_scan_host_address(&host.address))
                    .unwrap_or_else(|| LAN_SCAN_MISSING_VALUE.to_string()),
                discovered_tone: lan_scan_discovered_tone(&m.status),
                status: self.i18n.t(lan_scan_status_key(&m.status)),
                status_color: self.lan_scan_status_color(&m.status),
                fingerprint: lan_scan_match_fingerprint(&m.status),
                applicable: self.lan_scan_match_applicable(m),
            });
        }
        rows
    }

    fn lan_scan_status_color(&self, status: &DiscoveryMatchStatus) -> u32 {
        let ui = self.tokens.ui;
        match status {
            DiscoveryMatchStatus::AddressChanged { .. } => ui.accent,
            DiscoveryMatchStatus::Suggested { .. }
            | DiscoveryMatchStatus::MultipleMatches { .. } => ui.warning,
            DiscoveryMatchStatus::UpToDate { .. } | DiscoveryMatchStatus::NotFound => ui.text_muted,
        }
    }

    fn lan_scan_datum(
        &self,
        text: &str,
        tone: MonospaceDatumTone,
        max_chars: Option<usize>,
    ) -> Div {
        let mut options =
            MonospaceDatumOptions::new(tone).text_size(self.tokens.metrics.ui_text_xs);
        if let Some(max_chars) = max_chars {
            options = options.max_chars(max_chars);
        }
        oxideterm_gpui_ui::monospace_datum(
            &self.tokens,
            text,
            Some(settings_mono_font_family(self.settings_store.settings())),
            options,
        )
    }
}
