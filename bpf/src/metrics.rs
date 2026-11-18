use crate::maps::{FLOW_METRICS_RX, FLOW_METRICS_TX};
use crate::parsing::names::{extract_tc_hostname, extract_xdp_hostname};
use aya_ebpf::programs::{TcContext, XdpContext};
use mizn_common::bpf::{FlowKey, FlowMetrics};

// Avoid compiler-generated memset calls. bpf-linker rejects memset in eBPF
// programs, so initialize every field explicitly.
#[inline(always)]
unsafe fn new_metrics(bytes: u64, packets: u64, tcp_flags: u8) -> FlowMetrics {
    let mut value = core::mem::MaybeUninit::<FlowMetrics>::uninit();
    let ptr = value.as_mut_ptr();

    (*ptr).bytes = bytes;
    (*ptr).packets = packets;
    (*ptr).tcp_flags = tcp_flags;
    (*ptr)._explicit_padding_0 = 0;
    (*ptr)._explicit_padding_1 = 0;
    (*ptr)._explicit_padding_2 = 0;

    let mut i = 0;
    while i < 64 {
        (*ptr).sni[i] = 0;
        i += 1;
    }

    value.assume_init()
}

#[inline(always)]
pub unsafe fn update_metrics(key: &FlowKey, pkt_len: u64, flags: u8) {
    if let Some(m) = FLOW_METRICS_RX.get_ptr_mut(key) {
        (*m).bytes += pkt_len;
        (*m).packets += 1;
        (*m).tcp_flags |= flags;
    } else {
        let fresh = new_metrics(pkt_len, 1, flags);
        let _ = FLOW_METRICS_RX.insert(key, &fresh, 0);
    }
}

#[inline(always)]
pub unsafe fn update_metrics_with_sni(
    ctx: &XdpContext,
    key: &FlowKey,
    pkt_len: u64,
    flags: u8,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
) {
    if let Some(m) = FLOW_METRICS_RX.get_ptr_mut(key) {
        (*m).bytes += pkt_len;
        (*m).packets += 1;
        (*m).tcp_flags |= flags;
        if (*m).sni[0] == 0 {
            let _ = extract_xdp_hostname(ctx, protocol, dst_port, payload_off, &mut (*m).sni);
        }
    } else {
        let mut fresh = new_metrics(pkt_len, 1, flags);
        let _ = extract_xdp_hostname(ctx, protocol, dst_port, payload_off, &mut fresh.sni);
        let _ = FLOW_METRICS_RX.insert(key, &fresh, 0);
    }
}

/// Account a packet seen by the TC egress hook. This deliberately does not
/// share the XDP map: XDP can only observe ingress packets.
#[inline(always)]
pub unsafe fn update_tx_metrics(key: &FlowKey, pkt_len: u64, flags: u8) {
    if let Some(m) = FLOW_METRICS_TX.get_ptr_mut(key) {
        (*m).bytes += pkt_len;
        (*m).packets += 1;
        (*m).tcp_flags |= flags;
    } else {
        let fresh = new_metrics(pkt_len, 1, flags);
        let _ = FLOW_METRICS_TX.insert(key, &fresh, 0);
    }
}

/// Account an egress packet and retain the first hostname observed for its
/// flow. Client TLS handshakes normally travel in this direction, so parsing
/// only at XDP ingress would never populate SNI for local clients.
#[inline(always)]
pub unsafe fn update_tx_metrics_with_sni(
    ctx: &TcContext,
    key: &FlowKey,
    pkt_len: u64,
    flags: u8,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
) {
    if let Some(m) = FLOW_METRICS_TX.get_ptr_mut(key) {
        (*m).bytes += pkt_len;
        (*m).packets += 1;
        (*m).tcp_flags |= flags;
        if (*m).sni[0] == 0 {
            let _ = extract_tc_hostname(ctx, protocol, dst_port, payload_off, &mut (*m).sni);
        }
    } else {
        let mut fresh = new_metrics(pkt_len, 1, flags);
        let _ = extract_tc_hostname(ctx, protocol, dst_port, payload_off, &mut fresh.sni);
        let _ = FLOW_METRICS_TX.insert(key, &fresh, 0);
    }
}
