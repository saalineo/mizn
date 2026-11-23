use rusqlite::{Connection, Result, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const QUEUE_CAPACITY: usize = 1_024;
const BATCH_SIZE: usize = 256;
const BATCH_DELAY: Duration = Duration::from_millis(200);

#[derive(Debug)]
pub enum SecurityWrite {
    ArpEntry {
        ip: String,
        mac: String,
        last_seen: u64,
    },
    ThreatAlert {
        alert_type: &'static str,
        attacker_ip: String,
        target_port: u16,
    },
}

pub type SecurityWriteSender = mpsc::SyncSender<SecurityWrite>;

pub fn start(db: Arc<Mutex<Connection>>) -> SecurityWriteSender {
    let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
    std::thread::Builder::new()
        .name("mizn-security-db".into())
        .spawn(move || run(db, rx))
        .expect("failed to spawn security database writer");
    tx
}

fn run(db: Arc<Mutex<Connection>>, rx: mpsc::Receiver<SecurityWrite>) {
    while let Ok(first) = rx.recv() {
        let mut writes = vec![first];
        let deadline = Instant::now() + BATCH_DELAY;
        while writes.len() < BATCH_SIZE {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match rx.recv_timeout(remaining) {
                Ok(write) => writes.push(write),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }

        match db.lock() {
            Ok(mut conn) => {
                if let Err(error) = write_batch(&mut conn, writes) {
                    eprintln!("[miznd][security-db] write error: {error}");
                }
            }
            Err(error) => eprintln!("[miznd][security-db] database lock poisoned: {error}"),
        }
    }
}

fn write_batch(conn: &mut Connection, writes: Vec<SecurityWrite>) -> Result<()> {
    let mut arp_entries = HashMap::new();
    let mut alerts = Vec::new();
    for write in writes {
        match write {
            SecurityWrite::ArpEntry { ip, mac, last_seen } => {
                arp_entries.insert(ip, (mac, last_seen));
            }
            SecurityWrite::ThreatAlert {
                alert_type,
                attacker_ip,
                target_port,
            } => {
                alerts.push((alert_type, attacker_ip, target_port));
            }
        }
    }

    let transaction = conn.transaction()?;
    for (ip, (mac, last_seen)) in arp_entries {
        transaction.execute(
            "INSERT INTO arp_registry (ip, mac, last_seen)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, last_seen = excluded.last_seen",
            params![ip, mac, last_seen as i64],
        )?;
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for (alert_type, attacker_ip, target_port) in alerts {
        transaction.execute(
            "INSERT INTO threat_alerts (ts, alert_type, attacker_ip, target_port)
             VALUES (?1, ?2, ?3, ?4)",
            params![ts, alert_type, attacker_ip, target_port as i64],
        )?;
    }
    transaction.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_coalesces_arp_updates() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE threat_alerts (ts INTEGER, alert_type TEXT, attacker_ip TEXT, target_port INTEGER);
             CREATE TABLE arp_registry (ip TEXT PRIMARY KEY, mac TEXT, last_seen INTEGER);",
        )
        .unwrap();

        write_batch(
            &mut conn,
            vec![
                SecurityWrite::ArpEntry {
                    ip: "192.0.2.1".into(),
                    mac: "old".into(),
                    last_seen: 1,
                },
                SecurityWrite::ArpEntry {
                    ip: "192.0.2.1".into(),
                    mac: "new".into(),
                    last_seen: 2,
                },
                SecurityWrite::ThreatAlert {
                    alert_type: "HONEY_PORT_TRIGGER",
                    attacker_ip: "192.0.2.2".into(),
                    target_port: 23,
                },
            ],
        )
        .unwrap();

        let entry: (String, u64) = conn
            .query_row("SELECT mac, last_seen FROM arp_registry", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(entry, ("new".into(), 2));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM threat_alerts", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}
