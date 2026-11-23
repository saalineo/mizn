use crate::app::AppState;
use crate::config::{C_ALERT, C_BLOCKED, C_BORDER, C_DIM};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, List, ListItem},
};

pub fn draw_security_panel(f: &mut Frame, app: &AppState, area: Rect) {
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let mut alert_items = vec![ListItem::new(Span::styled(
        format!(
            "  Scan window: inbound max {}/20 · outbound max {}/20",
            app.telemetry.inbound_scan_max_ports, app.telemetry.outbound_scan_max_ports,
        ),
        Style::default().fg(C_DIM),
    ))];
    alert_items.extend(app
        .telemetry
        .active_port_scans
        .iter()
        .map(|scan| {
            ListItem::new(Span::styled(
                format!(
                    "  {} scan: {} ports from {}",
                    if scan.outbound { "OUTBOUND" } else { "INBOUND" },
                    scan.distinct_ports,
                    scan_source(scan.source_ip),
                ),
                Style::default().fg(C_ALERT).add_modifier(Modifier::BOLD),
            ))
        })
        );
    if app.telemetry.port_scan_detection_degraded {
        alert_items.push(ListItem::new(Span::styled(
            "  PORT-SCAN DETECTION DEGRADED",
            Style::default().fg(C_ALERT).add_modifier(Modifier::BOLD),
        )));
    }
    alert_items.extend(app.telemetry.recent_alerts.iter().rev().map(|msg| {
        ListItem::new(Span::styled(
            format!("  {}", msg),
            Style::default().fg(C_ALERT),
        ))
    }));
    let alert_items: Vec<ListItem> = if alert_items.is_empty() {
        vec![ListItem::new(Span::styled(
            "    No anomalies detected",
            Style::default().fg(C_DIM),
        ))]
    } else {
        alert_items
            .into_iter()
            .take(halves[0].height.saturating_sub(2) as usize)
            .collect()
    };

    let alert_list = List::new(alert_items).block(
        Block::default()
            .title(Span::styled(
                "   THREAT LOG ",
                Style::default().fg(C_ALERT).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(alert_list, halves[0]);

    let blocked_items: Vec<ListItem> = if app.blocked_ips.is_empty() {
        vec![ListItem::new(Span::styled(
            "    No blocked IPs — press [B] to drop top host",
            Style::default().fg(C_DIM),
        ))]
    } else {
        app.blocked_ips
            .iter()
            .rev()
            .take(halves[1].height.saturating_sub(3) as usize)
            .map(|(_, entry)| {
                ListItem::new(Span::styled(
                    format!("  {}", entry),
                    Style::default().fg(C_BLOCKED).add_modifier(Modifier::BOLD),
                ))
            })
            .collect()
    };

    let blocked_list = List::new(blocked_items).block(
        Block::default()
            .title(Span::styled(
                "  XDP FIREWALL — BLOCKED IPs ",
                Style::default().fg(C_BLOCKED).add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(C_BORDER)),
    );
    f.render_widget(blocked_list, halves[1]);
}

fn scan_source(source_ip: [u8; 16]) -> String {
    if source_ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        std::net::Ipv4Addr::from([source_ip[12], source_ip[13], source_ip[14], source_ip[15]])
            .to_string()
    } else {
        std::net::Ipv6Addr::from(source_ip).to_string()
    }
}
