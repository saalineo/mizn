use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, LruPerCpuHashMap, PerCpuArray};
use mizn_common::bpf::{FlowKey, FlowMetrics, ScanKey, ScanObservation};

// Keep directions in separate maps.  Direction is a property of the hook that
// observed the packet, not a property that can reliably be inferred from a
// five-tuple later in userspace.
// Flow cardinality is controlled by remote peers, so a fixed hash map can be
// exhausted by a scan and then permanently stop accounting for new flows. The
// LRU map keeps recently active flows while evicting inactive ones when full.
#[map]
pub static FLOW_METRICS_RX: LruPerCpuHashMap<FlowKey, FlowMetrics> =
    LruPerCpuHashMap::with_max_entries(10_240, 0);

#[map]
pub static FLOW_METRICS_TX: LruPerCpuHashMap<FlowKey, FlowMetrics> =
    LruPerCpuHashMap::with_max_entries(10_240, 0);

// Probe keys are fixed-size and deliberately not LRU: an eviction would hide
// lost coverage. Failed inserts are counted and reported as degraded instead.
#[map]
pub static PORT_SCAN_RX: HashMap<ScanKey, ScanObservation> = HashMap::with_max_entries(16_384, 0);

#[map]
pub static PORT_SCAN_TX: HashMap<ScanKey, ScanObservation> = HashMap::with_max_entries(16_384, 0);

// Index 0 is inbound saturation; index 1 is outbound saturation.
#[map]
pub static PORT_SCAN_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

#[map]
pub static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static BLOCKLIST_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);
