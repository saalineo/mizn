//! Honey-port active deception module.
//!
//! Binds lightweight TCP listeners on known attacker-targeted ports:
//!   - 21   → FTP
//!   - 23   → Telnet
//!   - 2323 → Mirai botnet probe
//!
//! Any inbound connection is immediately closed after the attacker IP and
//! targeted port are logged to the `threat_alerts` SQLite table.

use crate::features::security_writer::{SecurityWrite, SecurityWriteSender};
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Ports that legitimate software has no reason to contact.
const HONEY_PORTS: &[u16] = &[21, 23, 2323];

/// Spawn async Tokio tasks for all honey-port listeners.
pub fn start(db_writes: SecurityWriteSender, alert_tx: tokio::sync::mpsc::UnboundedSender<String>) {
    for &port in HONEY_PORTS {
        let db_writes = db_writes.clone();
        let alert_tx = alert_tx.clone();
        tokio::spawn(async move {
            let addr = format!("0.0.0.0:{port}");
            let listener = match TcpListener::bind(&addr).await {
                Ok(l) => {
                    eprintln!("[miznd][honey] Listening on {addr}");
                    l
                }
                Err(e) => {
                    eprintln!("[miznd][honey] Failed to bind {addr}: {e}");
                    return;
                }
            };

            loop {
                match listener.accept().await {
                    Ok((socket, remote)) => {
                        // Drop the socket immediately — the tarpit sends nothing.
                        drop(socket);
                        let _ = alert_tx.send(format!("HONEY TRAP: {remote} hit port {port}"));
                        handle_trigger(&db_writes, remote, port);
                    }
                    Err(e) => {
                        eprintln!("[miznd][honey] Accept error on port {port}: {e}");
                    }
                }
            }
        });
    }
}

fn handle_trigger(db_writes: &SecurityWriteSender, remote: SocketAddr, port: u16) {
    let attacker_ip = remote.ip().to_string();
    eprintln!("[miznd][honey][ALERT] HONEY_PORT_TRIGGER → attacker={attacker_ip} port={port}");

    if let Err(error) = db_writes.try_send(SecurityWrite::ThreatAlert {
        alert_type: "HONEY_PORT_TRIGGER",
        attacker_ip,
        target_port: port,
    }) {
        eprintln!("[miznd][honey] security database queue unavailable: {error}");
    }
}
