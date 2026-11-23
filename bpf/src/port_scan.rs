use aya_ebpf::{helpers::bpf_ktime_get_ns, maps::HashMap};
use mizn_common::bpf::{ScanKey, ScanObservation};

use crate::maps::PORT_SCAN_DROPS;

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

#[inline(always)]
pub fn record_probe(
    map: &HashMap<ScanKey, ScanObservation>,
    drop_slot: u32,
    source_ip: [u8; 16],
    destination_port: u16,
    flags: u8,
) {
    if flags & TCP_SYN == 0 || flags & TCP_ACK != 0 {
        return;
    }

    let key = ScanKey {
        source_ip,
        destination_port,
        _alignment_padding: [0; 6],
    };
    let observation = ScanObservation {
        last_seen_ns: unsafe { bpf_ktime_get_ns() },
    };
    if map.insert(&key, &observation, 0).is_err()
        && let Some(drop_count) = PORT_SCAN_DROPS.get_ptr_mut(drop_slot)
    {
        unsafe { *drop_count = (*drop_count).saturating_add(1) };
    }
}
