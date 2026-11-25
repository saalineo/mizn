use crate::core::database;
use crate::features::process_map::SocketsMap;
use aya::maps::{
    HashMap as BpfHashMap, MapData, PerCpuArray as BpfPerCpuArray,
    PerCpuHashMap as BpfPerCpuHashMap,
};
use mizn_common::bpf::{FlowKey, FlowMetrics, ScanKey, ScanObservation};
use mizn_common::ipc::{IpcAddress, IpcCommand, IpcPortScan, IpcProcessMetrics, IpcState};
use rkyv::Infallible;
use rkyv::ser::Serializer;
use rkyv::ser::serializers::{BufferScratch, BufferSerializer, CompositeSerializer};
use rusqlite::Connection;
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;

const TELEMETRY_BUFFER_SIZE: usize = 524288;
const AGGREGATION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const BLOCK_DURATION: Duration = Duration::from_secs(15 * 60);
const BLOCKLIST_V4_CAPACITY: usize = 1_024;
const BLOCKLIST_V6_CAPACITY: usize = 256;
const PORT_SCAN_WINDOW_NS: u64 = 30_000_000_000;
const PORT_SCAN_THRESHOLD: u16 = 20;

pub struct CoreLoopArgs {
    pub bpf: aya::Ebpf,
    pub cmd_rx: tokio::sync::mpsc::UnboundedReceiver<IpcCommand>,
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
    let mut unavailable_maps = HashSet::new();
    let mut active_blocks = HashMap::<IpcAddress, Instant>::new();
    let mut installed_v4 = HashSet::new();
    let mut installed_v6 = HashSet::new();
    let mut port_scan_drop_total = 0u64;
    let mut port_scan_degraded_until = None;

    loop {
        tokio::time::sleep(AGGREGATION_INTERVAL).await;

        let now = Instant::now();
        while let Ok(command) = args.cmd_rx.try_recv() {
            match command {
                IpcCommand::BlockIp(address) if is_protected_address(&address) => {
                    eprintln!("[miznd] refusing to block protected address: {address:?}");
                }
                IpcCommand::BlockIp(address) => {
                    if !can_add_block(&active_blocks, &address) {
                        eprintln!("[miznd] refusing {address:?}: blocklist is full");
                    } else {
                        active_blocks.insert(address.clone(), now + BLOCK_DURATION);
                        eprintln!(
                            "[miznd] blocking {address:?} for {}s",
                            BLOCK_DURATION.as_secs()
                        );
                    }
                }
                IpcCommand::UnblockIp(address) => {
                    active_blocks.remove(&address);
                    eprintln!("[miznd] unblocked {address:?}");
                }
            }
        }
        expire_blocks(&mut active_blocks, now);

        let desired_v4 = active_blocks
            .keys()
            .filter_map(|address| match address {
                IpcAddress::V4(bytes) => Some(u32::from_ne_bytes(*bytes)),
                IpcAddress::V6(_) => None,
            })
            .collect::<HashSet<_>>();
        let desired_v6 = active_blocks
            .keys()
            .filter_map(|address| match address {
                IpcAddress::V4(_) => None,
                IpcAddress::V6(bytes) => Some(*bytes),
            })
            .collect::<HashSet<_>>();

        match args.bpf.map_mut("BLOCKLIST") {
            Some(map) => match BpfHashMap::<_, u32, u8>::try_from(map) {
                Ok(mut blocklist) => {
                    sync_blocklist(&mut blocklist, &desired_v4, &mut installed_v4, "BLOCKLIST");
                }
                Err(error) => {
                    if unavailable_maps.insert("BLOCKLIST") {
                        eprintln!("[miznd] BLOCKLIST map is unusable: {error}");
                    }
                }
            },
            None => {
                if unavailable_maps.insert("BLOCKLIST") {
                    eprintln!("[miznd] BPF object is missing required BLOCKLIST map");
                }
            }
        }

        match args.bpf.map_mut("BLOCKLIST_V6") {
            Some(map) => match BpfHashMap::<_, [u8; 16], u8>::try_from(map) {
                Ok(mut blocklist) => {
                    sync_blocklist(
                        &mut blocklist,
                        &desired_v6,
                        &mut installed_v6,
                        "BLOCKLIST_V6",
                    );
                }
                Err(error) => {
                    if unavailable_maps.insert("BLOCKLIST_V6") {
                        eprintln!("[miznd] BLOCKLIST_V6 map is unusable: {error}");
                    }
                }
            },
            None => {
                if unavailable_maps.insert("BLOCKLIST_V6") {
                    eprintln!("[miznd] BPF object is missing required BLOCKLIST_V6 map");
                }
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
            let Some(map) = args.bpf.map_mut(map_name) else {
                if unavailable_maps.insert(map_name) {
                    eprintln!("[miznd] BPF object is missing required {map_name} map");
                }
                continue;
            };
            let flow_map = match BpfPerCpuHashMap::<_, FlowKey, FlowMetrics>::try_from(map) {
                Ok(map) => map,
                Err(error) => {
                    if unavailable_maps.insert(map_name) {
                        eprintln!("[miznd] {map_name} map is unusable: {error}");
                    }
                    continue;
                }
            };
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

        let port_scan_summary = refresh_port_scans(&mut args.bpf, &mut unavailable_maps);
        if port_scan_summary.drops > port_scan_drop_total {
            port_scan_degraded_until = Some(now + Duration::from_nanos(PORT_SCAN_WINDOW_NS));
        }
        port_scan_drop_total = port_scan_summary.drops;
        global_state.active_port_scans = port_scan_summary.active_scans;
        global_state.inbound_scan_max_ports = port_scan_summary.inbound_max_ports;
        global_state.outbound_scan_max_ports = port_scan_summary.outbound_max_ports;
        global_state.port_scan_detection_degraded =
            !port_scan_summary.available || port_scan_degraded_until.is_some_and(|until| until > now);

        global_state.finalize_tick(dtx, drx);

        while let Ok(msg) = args.ui_alert_rx.try_recv() {
            global_state.push_alert(msg);
        }

        let mut new_alerts = Vec::new();
        for pm in global_state.active_process_telemetry.values() {
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

struct PortScanSummary {
    active_scans: Vec<IpcPortScan>,
    inbound_max_ports: u16,
    outbound_max_ports: u16,
    drops: u64,
    available: bool,
}

fn refresh_port_scans(
    bpf: &mut aya::Ebpf,
    unavailable_maps: &mut HashSet<&'static str>,
) -> PortScanSummary {
    let now_ns = monotonic_ns();
    let mut scans = Vec::new();
    let mut available = true;
    let mut inbound_max_ports = 0;
    let mut outbound_max_ports = 0;

    for (map_name, outbound) in [("PORT_SCAN_RX", false), ("PORT_SCAN_TX", true)] {
        let Some(map) = bpf.map_mut(map_name) else {
            if unavailable_maps.insert(map_name) {
                eprintln!("[miznd] BPF object is missing required {map_name} map");
            }
            available = false;
            continue;
        };
        let Ok(mut observations) = BpfHashMap::<_, ScanKey, ScanObservation>::try_from(map) else {
            if unavailable_maps.insert(map_name) {
                eprintln!("[miznd] {map_name} map is unusable");
            }
            available = false;
            continue;
        };

        let entries = observations
            .iter()
            .filter_map(|entry| entry.ok())
            .collect::<Vec<_>>();
        let (counts, stale_keys) = summarize_port_scans(&entries, now_ns);
        for key in stale_keys {
            // A concurrent refresh can re-add this probe; the next tick
            // observes it again, while stale entries cannot pin the map.
            let _ = observations.remove(&key);
        }
        let max_ports = counts.values().copied().max().unwrap_or_default();
        if outbound {
            outbound_max_ports = max_ports;
        } else {
            inbound_max_ports = max_ports;
        }
        scans.extend(
            counts
                .into_iter()
                .filter_map(|(source_ip, distinct_ports)| {
                    (distinct_ports >= PORT_SCAN_THRESHOLD).then_some(IpcPortScan {
                        source_ip,
                        distinct_ports,
                        outbound,
                    })
                }),
        );
    }

    let mut drops = 0u64;
    match bpf.map_mut("PORT_SCAN_DROPS") {
        Some(map) => match BpfPerCpuArray::<_, u64>::try_from(map) {
            Ok(counters) => {
                for slot in 0..2 {
                    if let Ok(values) = counters.get(&slot, 0) {
                        drops += values.iter().copied().sum::<u64>();
                    }
                }
            }
            Err(error) => {
                if unavailable_maps.insert("PORT_SCAN_DROPS") {
                    eprintln!("[miznd] PORT_SCAN_DROPS map is unusable: {error}");
                }
                available = false;
            }
        },
        None => {
            if unavailable_maps.insert("PORT_SCAN_DROPS") {
                eprintln!("[miznd] BPF object is missing required PORT_SCAN_DROPS map");
            }
            available = false;
        }
    }

    scans.sort_by_key(|scan| (scan.outbound, scan.source_ip));
    PortScanSummary {
        active_scans: scans,
        inbound_max_ports,
        outbound_max_ports,
        drops,
        available,
    }
}

fn summarize_port_scans(
    entries: &[(ScanKey, ScanObservation)],
    now_ns: u64,
) -> (HashMap<[u8; 16], u16>, Vec<ScanKey>) {
    let mut counts = HashMap::<[u8; 16], u16>::new();
    let mut stale_keys = Vec::new();
    for (key, observation) in entries {
        if now_ns.saturating_sub(observation.last_seen_ns) < PORT_SCAN_WINDOW_NS {
            *counts.entry(key.source_ip).or_default() += 1;
        } else {
            stale_keys.push(*key);
        }
    }
    (counts, stale_keys)
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(ts.tv_nsec as u64)
    } else {
        0
    }
}

fn sync_blocklist<T, K>(
    map: &mut BpfHashMap<T, K, u8>,
    desired: &HashSet<K>,
    installed: &mut HashSet<K>,
    name: &str,
) where
    T: BorrowMut<MapData>,
    K: aya::Pod + Copy + Eq + Hash + std::fmt::Debug,
{
    for key in installed.difference(desired).copied().collect::<Vec<_>>() {
        match map.remove(&key) {
            Ok(()) => {
                installed.remove(&key);
            }
            Err(error) => eprintln!("[miznd] failed to remove {key:?} from {name}: {error}"),
        }
    }
    for key in desired.difference(installed).copied().collect::<Vec<_>>() {
        match map.insert(key, 1, 0) {
            Ok(()) => {
                installed.insert(key);
            }
            Err(error) => eprintln!("[miznd] failed to insert {key:?} into {name}: {error}"),
        }
    }
}

fn expire_blocks(blocks: &mut HashMap<IpcAddress, Instant>, now: Instant) {
    blocks.retain(|_, expires_at| *expires_at > now);
}

fn can_add_block(blocks: &HashMap<IpcAddress, Instant>, address: &IpcAddress) -> bool {
    let limit = match address {
        IpcAddress::V4(_) => BLOCKLIST_V4_CAPACITY,
        IpcAddress::V6(_) => BLOCKLIST_V6_CAPACITY,
    };
    blocks.contains_key(address)
        || blocks
            .keys()
            .filter(|active| std::mem::discriminant(*active) == std::mem::discriminant(address))
            .count()
            < limit
}

fn is_protected_address(address: &IpcAddress) -> bool {
    is_protected_by_policy(address, &protected_network_addresses())
}

fn is_protected_by_policy(address: &IpcAddress, protected: &HashSet<IpcAddress>) -> bool {
    match address {
        IpcAddress::V4(bytes) if bytes[0] == 127 => true,
        IpcAddress::V6(bytes) if *bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => true,
        _ => protected.contains(address),
    }
}

fn protected_network_addresses() -> HashSet<IpcAddress> {
    let mut protected = HashSet::new();

    if let Ok(routes) = std::fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let (Some(destination), Some(gateway), Some(flags)) =
                (fields.get(1), fields.get(2), fields.get(3))
            else {
                continue;
            };
            if *destination == "00000000"
                && u16::from_str_radix(flags, 16).is_ok_and(|flags| flags & 0x2 != 0)
                && let Ok(gateway) = u32::from_str_radix(gateway, 16)
            {
                protected.insert(IpcAddress::V4(gateway.to_ne_bytes()));
            }
        }
    }

    if let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for line in routes.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let (Some(destination), Some(prefix), Some(gateway)) =
                (fields.first(), fields.get(1), fields.get(4))
            else {
                continue;
            };
            if *destination == "00000000000000000000000000000000" && *prefix == "00" {
                if let Some(gateway) = parse_ipv6_hex(gateway) {
                    protected.insert(IpcAddress::V6(gateway));
                }
            }
        }
    }

    if let Ok(resolv_conf) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in resolv_conf.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("nameserver") {
                continue;
            }
            match fields.next().and_then(|value| value.parse::<IpAddr>().ok()) {
                Some(IpAddr::V4(address)) => {
                    protected.insert(IpcAddress::V4(address.octets()));
                }
                Some(IpAddr::V6(address)) => {
                    protected.insert(IpcAddress::V6(address.octets()));
                }
                None => {}
            }
        }
    }

    protected
}

fn parse_ipv6_hex(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

pub fn resolve_flow(reg: &SocketsMap, key: &FlowKey, is_tx: bool) -> Option<(i32, String)> {
    // Direction comes from the capture hook.  Only the local endpoint is used
    // for attribution, never to determine direction.
    let local_port = if is_tx {
        key.source_port
    } else {
        key.destination_port
    };
    // Unresolved flows go to pid 0 so aggregate throughput isn't under-counted.
    Some(
        reg.get(&(key.protocol, local_port))
            .cloned()
            .unwrap_or_else(|| (0, String::from("unattributed"))),
    )
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
    // Take ownership of every current connection before spawning writes so a
    // stalled client never keeps the aggregation loop (or the connection
    // registry lock) waiting. A healthy client is added back by its task.
    let clients = {
        let mut guard = conns.write().await;
        std::mem::take(&mut *guard)
    };
    let frame: Arc<[u8]> = Arc::from(data);

    for mut client in clients {
        let conns = Arc::clone(conns);
        let frame = Arc::clone(&frame);
        tokio::spawn(async move {
            match tokio::time::timeout(
                CLIENT_WRITE_TIMEOUT,
                write_telemetry_frame(&mut client, frame.as_ref()),
            )
            .await
            {
                Ok(Ok(())) => conns.write().await.push(client),
                Ok(Err(error)) => {
                    eprintln!("[miznd] dropping telemetry client after write error: {error}");
                }
                Err(_) => {
                    eprintln!(
                        "[miznd] dropping telemetry client after {}s write timeout",
                        CLIENT_WRITE_TIMEOUT.as_secs()
                    );
                }
            }
        });
    }
}

async fn write_telemetry_frame<W>(writer: &mut W, data: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(data).await
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCKLIST_V6_CAPACITY, PORT_SCAN_WINDOW_NS, can_add_block, expire_blocks,
        is_protected_address, is_protected_by_policy, summarize_port_scans, write_telemetry_frame,
    };
    use mizn_common::bpf::{ScanKey, ScanObservation};
    use mizn_common::ipc::IpcAddress;
    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn writes_length_prefixed_telemetry_frame() {
        let (mut writer, mut reader) = duplex(64);
        write_telemetry_frame(&mut writer, b"state").await.unwrap();

        let mut frame = [0; 9];
        reader.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..4], &(5u32).to_be_bytes());
        assert_eq!(&frame[4..], b"state");
    }

    #[tokio::test]
    async fn stalled_telemetry_write_can_be_timed_out() {
        let (mut writer, _reader) = duplex(1);

        let result = tokio::time::timeout(
            Duration::from_millis(20),
            write_telemetry_frame(&mut writer, b"state"),
        )
        .await;

        assert!(result.is_err());
    }

    #[test]
    fn loopback_addresses_are_never_blockable() {
        assert!(is_protected_address(&IpcAddress::V4([127, 0, 0, 1])));
        assert!(is_protected_address(&IpcAddress::V6([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])));
    }

    #[test]
    fn gateways_and_resolvers_are_never_blockable() {
        let protected = HashSet::from([
            IpcAddress::V4([192, 0, 2, 1]),
            IpcAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53]),
        ]);

        assert!(is_protected_by_policy(
            &IpcAddress::V4([192, 0, 2, 1]),
            &protected
        ));
        assert!(is_protected_by_policy(
            &IpcAddress::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53]),
            &protected,
        ));
    }

    #[test]
    fn expired_blocks_are_removed() {
        let now = Instant::now();
        let mut blocks = HashMap::from([
            (IpcAddress::V4([192, 0, 2, 1]), now - Duration::from_secs(1)),
            (IpcAddress::V6([2; 16]), now + Duration::from_secs(1)),
        ]);

        expire_blocks(&mut blocks, now);

        assert_eq!(blocks.len(), 1);
        assert!(blocks.contains_key(&IpcAddress::V6([2; 16])));
    }

    #[test]
    fn blocklist_capacity_is_enforced_per_ip_family() {
        let now = Instant::now();
        let mut blocks = HashMap::new();
        for value in 0..BLOCKLIST_V6_CAPACITY {
            let mut address = [0; 16];
            address[0] = value as u8;
            blocks.insert(IpcAddress::V6(address), now);
        }

        assert!(!can_add_block(
            &blocks,
            &IpcAddress::V6([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        ));
        assert!(can_add_block(
            &blocks,
            &IpcAddress::V6([42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        ));
    }

    #[test]
    fn scan_summary_counts_distinct_fresh_ports_and_expires_old_ones() {
        let source = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 7];
        let fresh = ScanObservation {
            last_seen_ns: PORT_SCAN_WINDOW_NS * 2 - 1,
        };
        let stale = ScanObservation {
            last_seen_ns: PORT_SCAN_WINDOW_NS,
        };
        let key = |port| ScanKey {
            source_ip: source,
            destination_port: port,
            _alignment_padding: [0; 6],
        };
        let (counts, stale_keys) = summarize_port_scans(
            &[(key(22), fresh), (key(80), fresh), (key(443), stale)],
            PORT_SCAN_WINDOW_NS * 2,
        );

        assert_eq!(counts.get(&source), Some(&2));
        assert_eq!(stale_keys, vec![key(443)]);
    }
}
