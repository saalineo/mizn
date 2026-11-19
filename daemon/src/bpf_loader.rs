use anyhow::{Context, anyhow};
use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc};
use aya::{Ebpf, include_bytes_aligned};

pub struct BpfContext {
    pub ebpf: Ebpf,
}

impl BpfContext {
    pub fn load_and_attach(iface: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/mizn-ebpf"
        ))?;

        let program: &mut Xdp = bpf
            .program_mut("mizn_ebpf")
            .ok_or_else(|| anyhow!("BPF object is missing required XDP program 'mizn_ebpf'"))?
            .try_into()
            .context("BPF program 'mizn_ebpf' has an unexpected type")?;
        program.load()?;
        program.attach(iface, XdpFlags::default())?;

        // XDP has no egress path. Add a pass-through TC classifier solely to
        // account packets that actually leave this interface.
        match tc::qdisc_add_clsact(iface) {
            Ok(()) => {}
            // Another TC user may already own the clsact qdisc; attaching the
            // classifier below is still valid in that case.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err.into()),
        }
        let egress: &mut SchedClassifier = bpf
            .program_mut("mizn_tc_egress")
            .ok_or_else(|| anyhow!("BPF object is missing required TC program 'mizn_tc_egress'"))?
            .try_into()
            .context("BPF program 'mizn_tc_egress' has an unexpected type")?;
        egress.load()?;
        egress.attach(iface, TcAttachType::Egress)?;

        Ok(Self { ebpf: bpf })
    }
}
