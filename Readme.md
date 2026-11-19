# MIZN

[![Rust](https://img.shields.io/badge/Rust-2024-orange?logo=rust)](https://www.rust-lang.org/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![eBPF](https://img.shields.io/badge/telemetry-eBPF-4C8EDA)](https://ebpf.io/)
[![Aya](https://img.shields.io/badge/eBPF-Aya-4C8EDA)](https://aya-rs.dev/)
[![SQLite](https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite)](https://www.sqlite.org/)
[![Ratatui](https://img.shields.io/badge/interface-Ratatui-00A8E8)](https://ratatui.rs/)
[![Alerts](https://img.shields.io/badge/alerts-webhook%20%2B%20SMTP-5A45FF)](#build-and-run)

MIZN is a Linux network-monitoring daemon with a terminal UI. It watches traffic at the interface, turns counters into per-process telemetry where it can match a socket, and keeps a small local record of what it sees. It is aimed at people who want a view of a machine's network activity without shipping that telemetry to a hosted service.

MIZN needs elevated privileges. It attaches an XDP program, installs a TC egress classifier, opens a raw socket for ARP monitoring, and creates sockets under `/run` for the terminal UI.

## What MIZN does

- Tracks ingress and egress traffic on the selected interface.
- Associates flows with a process name and PID from a userspace socket snapshot when that mapping is available.
- Shows current process telemetry in a Ratatui-based terminal interface.
- Records flow and threat data in a local SQLite database.
- Raises alerts for SYN-without-ACK scan patterns and bandwidth thresholds.
- Listens on honey ports 21, 23, and 2323, then logs and reports connection attempts.
- Watches ARP traffic for a source IP address that changes MAC address.
- Can send alerts to a JSON webhook or SMTP relay. ClickHouse output is also available when configured.

## How it works

The eBPF side is deliberately small. An XDP program accounts for received traffic, while a pass-through TC classifier accounts for transmitted traffic. Neither program changes packet forwarding.

Once each second, the daemon reads those counters and combines them with the current socket-to-process map. The result is an `IpcState` snapshot containing process rates, destinations, TCP flags, and recent alerts. The daemon sends that snapshot over `/run/miznd.sock`; the TUI reads it from there. Control commands, such as blocking an IP, go back through `/run/miznd_cmd.sock`.

The daemon writes flow history and threat events to SQLite. Critical traffic alerts can create an on-demand PCAP file. Webhook and SMTP delivery run separately from telemetry aggregation, so an unavailable alert destination does not stop the monitoring loop.

## How it differs from typical network monitors

No single item here is exclusive to MIZN. The project combines several useful pieces in one local daemon, with a few trade-offs made explicit.

| Area | What MIZN does | Why it matters |
| --- | --- | --- |
| Directional accounting | An XDP program counts received traffic and a pass-through TC egress classifier counts transmitted traffic on the selected interface. | The daemon can report RX and TX rates separately without changing packet forwarding. |
| Process context | Every 500 ms, MIZN refreshes a local socket-to-process map. Each aggregation tick uses that map to attach a PID and process name to a flow when the local port can be resolved. | A remote address alone rarely tells you which local program opened the connection. |
| Local control plane | The TUI reads snapshots from `/run/miznd.sock` and sends control commands through `/run/miznd_cmd.sock`. The sockets are group-owned and use `0660` permissions. | Monitoring data and TUI control stay on the host instead of requiring a network listener or a hosted dashboard. |
| Detection sources | Network-rate and TCP-flag rules share an alert stream with ARP monitoring and honey ports on 21, 23, and 2323. Flow history and threat events go to SQLite. | One interface surfaces traffic anomalies, local-network identity changes, and inbound probes together. |
| Slow consumers | Telemetry writes run in per-client tasks. A client that cannot receive a frame within the timeout is removed, while aggregation continues for the remaining clients. | A stalled TUI cannot hold up telemetry collection for every other client. |
| Optional delivery | Webhook, SMTP, and ClickHouse output are enabled only through environment variables. Webhook work runs outside the aggregation loop and has a timeout. | The local daemon remains usable when a remote service is absent or unavailable. |

Process attribution is based on a userspace socket snapshot, so it can be unavailable or affected by short-lived connections and port reuse. MIZN is a monitoring and detection tool. It does not replace a firewall, an IDS signature engine, or normal host hardening.

## Build and run

MIZN currently targets Linux. Building the eBPF program requires the nightly Rust toolchain and `bpf-linker` 0.9.15.

```bash
cargo +nightly install bpf-linker --version 0.9.15
cargo xtask build
```

The included launcher creates the `mizn` socket group, builds the eBPF and userspace programs, starts the daemon, and offers to launch the TUI:

```bash
sudo ./run.sh
```

Set `MIZN_IFACE` before starting the daemon to choose an interface. If it is unset, MIZN selects an active non-loopback interface.

```bash
sudo MIZN_IFACE=eth0 ./run.sh
```

Optional alert and storage settings are read from the environment:

| Purpose | Variables |
| --- | --- |
| Webhook | `MIZN_WEBHOOK_URL` |
| SMTP | `MIZN_SMTP_RELAY`, `MIZN_SMTP_FROM`, `MIZN_SMTP_TO`, `MIZN_SMTP_USER`, `MIZN_SMTP_PASS` |
| ClickHouse | `MIZN_CH_URL`, `MIZN_CH_DB`, `MIZN_CH_USER`, `MIZN_CH_PASSWORD` |

Keep those values out of Git. The repository ignores common secret files, but it is still worth checking `git status` before committing.

## Test it

Run the daemon's test suite with:

```bash
cargo test -p mizndaemon
```

Check the userspace workspace with:

```bash
cargo check --workspace
```

Those checks cover the Rust code without attaching an eBPF program. For a smoke test of the full stack, use a Linux machine where you can run as root, build with `cargo xtask build`, start MIZN, and confirm that the TUI connects to `/run/miznd.sock`. The ARP monitor and eBPF attachment need the appropriate kernel support and privileges.

## License

MIZN is licensed under the [GNU General Public License v3.0](LICENSE).
