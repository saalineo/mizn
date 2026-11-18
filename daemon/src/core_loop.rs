use crate::core::database;
use crate::features::process_map::SocketsMap;
use aya::maps::{HashMap as BpfHashMap, PerCpuHashMap as BpfPerCpuHashMap};
use mizn_common::bpf::{FlowKey, FlowMetrics};
use mizn_common::ipc::{IpcProcessMetrics, IpcState};
use rkyv::ser::serializers::{BufferScratch, BufferSerializer, CompositeSerializer};
use rkyv::ser::Serializer;
use rkyv::Infallible;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

const TELEMETRY_BUFFER_SIZE: usize = 524288;
const AGGREGATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

pub struct CoreLoopArgs {
    pub bpf: aya::Ebpf,
    pub cmd_rx: tokio::sync::mpsc::UnboundedReceiver<u32>,
    pub ch_sender: Option<tokio::sync::mpsc::UnboundedSender<Vec<IpcProcessMetrics>>>,
    pub alert_tx: tokio::sync::mpsc::UnboundedSender<IpcState>,
    pub ui_alert_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    pub connections: Arc<RwLock<Vec<tokio::net::UnixStream>>>,
    pub socket_registry: Arc<RwLock<SocketsMap>>,
    pub db: Arc<Mutex<Connection>>,
}

pub async fn run(mut args: CoreLoopArgs) {
    // RX and TX maps can hold the same tuple independently, so direction is
    // part of the userspace shadow key as well.
    // Keep snapshots only for keys currently present in the bounded LRU maps.
    // This must remain bounded too: the kernel can evict a flow before it is
    // seen again, so no later update can naturally replace its old snapshot.
    let mut bpf_shadow: HashMap<(bool, FlowKey), FlowMetrics> = HashMap::with_capacity(20_480);
    let mut global_state = IpcState::default();
    let mut serial_buf = [0u8; TELEMETRY_BUFFER_SIZE];
    let mut scratch_buf = [0u8; 4096];

    loop {
        tokio::time::sleep(AGGREGATION_INTERVAL).await;

        if let Ok(mut blocklist) =
            BpfHashMap::<_, u32, u8>::try_from(args.bpf.map_mut("BLOCKLIST").unwrap())
        {
            while let Ok(ip) = args.cmd_rx.try_recv() {
                let _ = blocklist.insert(ip, 1, 0);
                eprintln!("[miznd] Blocked: {}", std::net::Ipv4Addr::from(ip.to_be()));
            }
        }

        let registry = args.socket_registry.read().await;
        let mut dtx = 0u64;
        let mut drx = 0u64;

        global_state
            .active_process_telemetry
            .values_mut()
            .for_each(|m| {
                m.temporal_transmission_accumulator = 0;
                m.temporal_reception_accumulator = 0;
            });

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (map_name, is_tx) in [("FLOW_METRICS_RX", false), ("FLOW_METRICS_TX", true)] {
            if let Ok(flow_map) = BpfPerCpuHashMap::<_, FlowKey, FlowMetrics>::try_from(
                args.bpf.map_mut(map_name).unwrap(),
            ) {
                let mut updates = Vec::new();
                let mut seen = HashSet::new();
                for r in flow_map.iter().filter_map(|r| r.ok()) {
                    let (key, per_cpu_metrics) = r;
                    seen.insert(key);
                    let mut metrics = FlowMetrics::default();
                    for m in per_cpu_metrics.iter() {
                        metrics.bytes += m.bytes;
                        metrics.packets += m.packets;
                        metrics.tcp_flags |= m.tcp_flags;
                        if metrics.sni[0] == 0 && m.sni[0] != 0 {
                            metrics.sni = m.sni;
                        }
                    }

                    let prev = bpf_shadow.entry((is_tx, key)).or_default();
                    // An LRU eviction followed by a new packet for the same
                    // tuple resets its counters. Treat that snapshot as a new
                    // flow instead of turning the reset into a wrapped u64
                    // delta.
                    let delta_bytes = metrics
                        .bytes
                        .checked_sub(prev.bytes)
                        .unwrap_or(metrics.bytes);
                    *prev = metrics;
                    if delta_bytes > 0 {
                        updates.push((key, metrics, delta_bytes));
                    }
                }

                // LRU eviction removes keys from the BPF map without notifying
                // userspace. Drop their corresponding snapshots after every
                // successful walk so the userspace table has the same bound as
                // the kernel flow table.
                bpf_shadow
                    .retain(|(shadow_is_tx, key), _| *shadow_is_tx != is_tx || seen.contains(key));

                if !updates.is_empty() {
                    for (key, metrics, delta_bytes) in updates {
                        // eBPF packet hooks do not run in the originating
                        // process context, so a port-only PID map would be
                        // both incomplete and unsafe under port reuse.  Use
                        // the userspace socket snapshot until attribution is
                        // implemented with a lifecycle-tracked flow key.
                        let resolved = resolve_flow(&registry, &key, is_tx);

                        if let Some((pid, name)) = resolved {
                            let protocol = proto_name(key.protocol);
                            let sni = String::from_utf8_lossy(&metrics.sni)
                                .trim_matches(char::from(0))
                                .to_string();
                            if let Ok(conn) = args.db.lock() {
                                let _ = database::record_flow(
                                    &conn,
                                    ts,
                                    pid,
                                    &name,
                                    delta_bytes,
                                    &sni,
                                    protocol,
                                );
                            }

                            let entry = global_state
                                .active_process_telemetry
                                .entry(pid)
                                .or_insert_with(|| IpcProcessMetrics::new(pid, name));
                            entry.update_from_delta(delta_bytes, is_tx, &metrics);
                            let remote_ip = if is_tx {
                                key.destination_ip
                            } else {
                                key.source_ip
                            };
                            let remote_ipv4 =
                                if remote_ip[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                                    Some(u32::from_be_bytes([
                                        remote_ip[12],
                                        remote_ip[13],
                                        remote_ip[14],
                                        remote_ip[15],
                                    ]))
                                } else {
                                    None
                                };
                            entry.last_resolved_remote_peer_ipv4 = remote_ipv4;
                            if !sni.is_empty() {
                                entry.sni = sni;
                            }

                            dtx += delta_bytes * (is_tx as u64);
                            drx += delta_bytes * (!is_tx as u64);
                        }
                    }
                }
            }
        }

        global_state.finalize_tick(dtx, drx);

        while let Ok(msg) = args.ui_alert_rx.try_recv() {
            global_state.push_alert(msg);
        }

        let mut new_alerts = Vec::new();
        for pm in global_state.active_process_telemetry.values() {
            let syn_no_ack = (pm.tcp_flags & 0x02 != 0) && (pm.tcp_flags & 0x10 == 0);
            if syn_no_ack {
                let msg = format!(
                    "Port Scan: {} (PID {})",
                    pm.process_nomenclature, pm.process_identifier
                );
                new_alerts.push(msg);
            }
            let high_bw = (pm.transmission_rate_bytes_per_second
                + pm.reception_rate_bytes_per_second)
                > 52_428_800; // 50MB/s
            if high_bw {
                let msg = format!(
                    "High Bandwidth: {} (PID {})",
                    pm.process_nomenclature, pm.process_identifier
                );
                new_alerts.push(msg);
            }
        }

        for msg in new_alerts {
            global_state.push_alert(msg);
        }

        let _ = args.alert_tx.send(global_state.clone());

        if let Some(ref ch_tx) = args.ch_sender {
            let rows: Vec<IpcProcessMetrics> = global_state
                .active_process_telemetry
                .values()
                .cloned()
                .collect();
            let _ = ch_tx.send(rows);
        }

        let len = {
            let mut ser = CompositeSerializer::new(
                BufferSerializer::new(&mut serial_buf),
                BufferScratch::new(&mut scratch_buf),
                Infallible,
            );
            if ser.serialize_value(&global_state).is_ok() {
                ser.pos()
            } else {
                0
            }
        };
        if len > 0 {
            broadcast(&args.connections, &serial_buf[..len]).await;
        }
    }
}

pub fn resolve_flow(reg: &SocketsMap, key: &FlowKey, is_tx: bool) -> Option<(i32, String)> {
    // Direction comes from the capture hook.  Only the local endpoint is used
    // for attribution, never to determine direction.
    let local_port = if is_tx {
        key.source_port
    } else {
        key.destination_port
    };
    reg.get(&local_port).map(|s| (s.0, s.1.clone()))
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        47 => "GRE",
        _ => "OTHER",
    }
}

async fn broadcast(conns: &Arc<RwLock<Vec<tokio::net::UnixStream>>>, data: &[u8]) {
    let mut guard = conns.write().await;
    let data_len = data.len() as u32;
    let mut active = Vec::with_capacity(guard.len());
    for mut c in guard.drain(..) {
        if c.write_u32(data_len).await.is_ok() && c.write_all(data).await.is_ok() {
            active.push(c);
        }
    }
    *guard = active;
}
