#![no_std]
#![no_main]

mod egress;
mod headers;
mod maps;
mod metrics;
mod parsing;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, xdp_action},
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn mizn_ebpf(ctx: XdpContext) -> u32 {
    match parsing::process_packet(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

/// TC runs on packets leaving the selected interface, so it is the source of
/// truth for transmission counters.  It is intentionally a pass-through
/// classifier: accounting must never affect forwarding.
#[classifier]
pub fn mizn_tc_egress(ctx: TcContext) -> i32 {
    let _ = egress::process_packet(&ctx);
    // Continue through any existing TC classifier chain.
    TC_ACT_PIPE
}
