//! Packet parsing for the TC egress classifier.
//!
//! TC packet data may be non-linear, so use `bpf_skb_load_bytes` through
//! `TcContext::load` instead of XDP's direct packet pointers.

use aya_ebpf::programs::TcContext;
use mizn_common::bpf::FlowKey;

use crate::headers::{EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};
use crate::metrics::{update_tx_metrics, update_tx_metrics_with_sni};
use crate::parsing::{
    ipv4_to_v6_mapped, make_flow_key, ETH_IPV4, ETH_IPV6, PROTO_ICMP, PROTO_ICMP6, PROTO_TCP,
    PROTO_UDP,
};

#[inline(always)]
fn load<T>(ctx: &TcContext, offset: usize) -> Result<T, ()> {
    ctx.load(offset).map_err(|_| ())
}

#[inline(always)]
pub fn process_packet(ctx: &TcContext) -> Result<(), ()> {
    let eth: EthernetHeader = load(ctx, 0)?;
    match u16::from_be(eth.ether_type) {
        ETH_IPV4 => process_ipv4(ctx, core::mem::size_of::<EthernetHeader>()),
        ETH_IPV6 => process_ipv6(ctx, core::mem::size_of::<EthernetHeader>()),
        _ => Ok(()),
    }
}

#[inline(always)]
fn process_ipv4(ctx: &TcContext, ip_offset: usize) -> Result<(), ()> {
    let ip: Ipv4Header = load(ctx, ip_offset)?;
    let ihl = ((ip.version_ihl & 0x0f) as usize) << 2;
    // Reject malformed headers before using their claimed transport offset.
    if ihl < core::mem::size_of::<Ipv4Header>() {
        return Err(());
    }

    let src_ip = ipv4_to_v6_mapped(ip.source_address);
    let dst_ip = ipv4_to_v6_mapped(ip.destination_address);
    process_transport(ctx, ip_offset + ihl, ip.protocol, src_ip, dst_ip)
}

#[inline(always)]
fn process_ipv6(ctx: &TcContext, ip_offset: usize) -> Result<(), ()> {
    let ip: Ipv6Header = load(ctx, ip_offset)?;
    process_transport(
        ctx,
        ip_offset + core::mem::size_of::<Ipv6Header>(),
        ip.next_header,
        ip.source_address,
        ip.destination_address,
    )
}

#[inline(always)]
fn process_transport(
    ctx: &TcContext,
    offset: usize,
    protocol: u8,
    source_ip: [u8; 16],
    destination_ip: [u8; 16],
) -> Result<(), ()> {
    let packet_len = ctx.len() as u64;
    let (source_port, destination_port, flags, payload_offset) = match protocol {
        PROTO_TCP => {
            let tcp: TcpHeader = load(ctx, offset)?;
            let header_len = ((tcp.data_offset_reserved >> 4) as usize) << 2;
            if header_len < core::mem::size_of::<TcpHeader>() {
                return Err(());
            }
            (
                u16::from_be(tcp.source_port),
                u16::from_be(tcp.destination_port),
                tcp.flags,
                offset + header_len,
            )
        }
        PROTO_UDP => {
            let udp: UdpHeader = load(ctx, offset)?;
            (
                u16::from_be(udp.source_port),
                u16::from_be(udp.destination_port),
                0,
                offset + core::mem::size_of::<UdpHeader>(),
            )
        }
        PROTO_ICMP | PROTO_ICMP6 => {
            let icmp: IcmpHeader = load(ctx, offset)?;
            (icmp.icmp_type as u16, icmp.code as u16, 0, offset)
        }
        _ => return Ok(()),
    };

    let key: FlowKey = unsafe {
        make_flow_key(
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
        )
    };
    unsafe {
        if protocol == PROTO_TCP || protocol == PROTO_UDP {
            update_tx_metrics_with_sni(
                ctx,
                &key,
                packet_len,
                flags,
                protocol,
                destination_port,
                payload_offset,
            );
        } else {
            update_tx_metrics(&key, packet_len, flags);
        }
    };
    Ok(())
}
