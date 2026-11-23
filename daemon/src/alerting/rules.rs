use super::{Alert, AlertConfig, AlertLevel, ALERT_COOLDOWN, PORT_SCAN_ALERT_COOLDOWN};
use mizn_common::ipc::{IpcPortScan, IpcState};
use std::time::Instant;

pub fn evaluate_rules(state: &IpcState, config: &AlertConfig, out: &mut Vec<Alert>) {
    for scan in &state.active_port_scans {
        out.push(Alert {
            timestamp: Instant::now(),
            level: AlertLevel::Critical,
            message: format!(
                " {} port scan: {} distinct ports from {}",
                if scan.outbound { "Outbound" } else { "Inbound" },
                scan.distinct_ports,
                scan_source(scan),
            ),
            trigger_pcap: true,
            cooldown_key: format!("port-scan:{}:{:?}", scan.outbound, scan.source_ip),
            cooldown: PORT_SCAN_ALERT_COOLDOWN,
        });
    }

    for pm in state.active_process_telemetry.values() {
        let total = pm.transmission_rate_bytes_per_second + pm.reception_rate_bytes_per_second;
        if total > config.high_bw_threshold {
            out.push(Alert {
                timestamp: Instant::now(),
                level: AlertLevel::Warning,
                message: format!(
                    " High Bandwidth: '{}' (PID {}) at {:.1} MB/s",
                    pm.process_nomenclature,
                    pm.process_identifier,
                    total as f64 / 1_048_576.0
                ),
                trigger_pcap: false,
                cooldown_key: format!("high-bandwidth:{}", pm.process_identifier),
                cooldown: ALERT_COOLDOWN,
            });
        }
    }

    let global = state.aggregate_reception_rate_bytes_per_second
        + state.aggregate_transmission_rate_bytes_per_second;
    if global > config.high_bw_threshold * 3 {
        out.push(Alert {
            timestamp: Instant::now(),
            level: AlertLevel::Critical,
            message: format!(
                " Global spike: {:.1} MB/s — possible DDoS or exfiltration",
                global as f64 / 1_048_576.0
            ),
            trigger_pcap: true,
            cooldown_key: "global-spike".to_string(),
            cooldown: ALERT_COOLDOWN,
        });
    }
}

fn scan_source(scan: &IpcPortScan) -> String {
    if scan.source_ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        std::net::Ipv4Addr::from([
            scan.source_ip[12],
            scan.source_ip[13],
            scan.source_ip[14],
            scan.source_ip[15],
        ])
        .to_string()
    } else {
        std::net::Ipv6Addr::from(scan.source_ip).to_string()
    }
}
