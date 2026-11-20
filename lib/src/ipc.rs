use crate::bpf::FlowMetrics;
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::HashMap;
use std::string::String;
use std::vec::Vec;

/// Maximum serialized command frame accepted by the command socket.
pub const IPC_COMMAND_MAX_FRAME_SIZE: usize = 64 * 1024;
/// Maximum serialized telemetry state frame accepted by the TUI.
pub const IPC_STATE_MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Archive, Deserialize, Serialize, Debug, Clone, PartialEq, Eq, Hash)]
#[archive(check_bytes)]
pub enum IpcAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub enum IpcCommand {
    BlockIp(IpcAddress),
    UnblockIp(IpcAddress),
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct IpcState {
    pub active_process_telemetry: HashMap<i32, IpcProcessMetrics>,
    pub aggregate_cumulative_bytes_transmitted: u64,
    pub aggregate_cumulative_bytes_received: u64,
    pub aggregate_transmission_rate_bytes_per_second: u64,
    pub aggregate_reception_rate_bytes_per_second: u64,
    pub global_peak_throughput_bytes_per_second: u64,
    pub transmission_history_ring_buffer: [u64; 60],
    pub reception_history_ring_buffer: [u64; 60],
    pub history_ring_buffer_cursor: usize,
    pub telemetry_initialization_timestamp_millis: u64,
    pub recent_alerts: Vec<String>,
}

impl Default for IpcState {
    fn default() -> Self {
        Self {
            active_process_telemetry: HashMap::with_capacity(1024),
            aggregate_cumulative_bytes_transmitted: 0,
            aggregate_cumulative_bytes_received: 0,
            aggregate_transmission_rate_bytes_per_second: 0,
            aggregate_reception_rate_bytes_per_second: 0,
            global_peak_throughput_bytes_per_second: 0,
            transmission_history_ring_buffer: [0; 60],
            reception_history_ring_buffer: [0; 60],
            history_ring_buffer_cursor: 0,
            telemetry_initialization_timestamp_millis: 0,
            recent_alerts: Vec::with_capacity(32),
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub struct IpcProcessMetrics {
    pub process_identifier: i32,
    pub process_nomenclature: String,
    pub cumulative_bytes_transmitted: u64,
    pub cumulative_bytes_received: u64,
    pub transmission_rate_bytes_per_second: u64,
    pub reception_rate_bytes_per_second: u64,
    pub temporal_transmission_accumulator: u64,
    pub temporal_reception_accumulator: u64,
    pub peak_throughput_bytes_per_second: u64,
    pub last_resolved_remote_peer_ipv4: Option<u32>,
    pub tcp_flags: u8,
    pub sni: String,
    pub cumulative_bytes_udp: u64,
}

impl IpcProcessMetrics {
    pub fn new(process_identifier: i32, process_nomenclature: String) -> Self {
        Self {
            process_identifier,
            process_nomenclature,
            cumulative_bytes_transmitted: 0,
            cumulative_bytes_received: 0,
            transmission_rate_bytes_per_second: 0,
            reception_rate_bytes_per_second: 0,
            temporal_transmission_accumulator: 0,
            temporal_reception_accumulator: 0,
            peak_throughput_bytes_per_second: 0,
            last_resolved_remote_peer_ipv4: None,
            tcp_flags: 0,
            sni: String::new(),
            cumulative_bytes_udp: 0,
        }
    }

    #[inline(always)]
    pub fn update_from_delta(&mut self, delta: u64, is_tx: bool, raw: &FlowMetrics) {
        if is_tx {
            self.cumulative_bytes_transmitted += delta;
            self.temporal_transmission_accumulator += delta;
        } else {
            self.cumulative_bytes_received += delta;
            self.temporal_reception_accumulator += delta;
        }
        self.tcp_flags |= raw.tcp_flags;
    }

    /// Publish the bytes collected during this one-second aggregation tick as
    /// rates and retain the largest combined rate observed for this process.
    #[inline(always)]
    pub fn finalize_tick(&mut self) {
        self.transmission_rate_bytes_per_second = self.temporal_transmission_accumulator;
        self.reception_rate_bytes_per_second = self.temporal_reception_accumulator;

        let throughput = self
            .transmission_rate_bytes_per_second
            .saturating_add(self.reception_rate_bytes_per_second);
        self.peak_throughput_bytes_per_second =
            self.peak_throughput_bytes_per_second.max(throughput);
    }
}

impl IpcState {
    #[inline(always)]
    pub fn finalize_tick(&mut self, tx_rate: u64, rx_rate: u64) {
        for process in self.active_process_telemetry.values_mut() {
            process.finalize_tick();
        }

        self.aggregate_transmission_rate_bytes_per_second = tx_rate;
        self.aggregate_reception_rate_bytes_per_second = rx_rate;

        let combined = tx_rate.saturating_add(rx_rate);
        if combined > self.global_peak_throughput_bytes_per_second {
            self.global_peak_throughput_bytes_per_second = combined;
        }

        self.transmission_history_ring_buffer[self.history_ring_buffer_cursor] = tx_rate;
        self.reception_history_ring_buffer[self.history_ring_buffer_cursor] = rx_rate;
        self.history_ring_buffer_cursor = (self.history_ring_buffer_cursor + 1) % 60;
    }

    #[inline(always)]
    pub fn push_alert(&mut self, alert: String) {
        if !self.recent_alerts.contains(&alert) {
            self.recent_alerts.push(alert);
            if self.recent_alerts.len() > 32 {
                self.recent_alerts.remove(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IpcProcessMetrics, IpcState};
    use std::string::String;

    #[test]
    fn finalizing_a_tick_publishes_process_rates_and_peak() {
        let mut state = IpcState::default();
        let mut process = IpcProcessMetrics::new(42, String::from("worker"));
        process.temporal_transmission_accumulator = 400;
        process.temporal_reception_accumulator = 600;
        process.peak_throughput_bytes_per_second = 900;
        state.active_process_telemetry.insert(42, process);

        state.finalize_tick(400, 600);

        let process = &state.active_process_telemetry[&42];
        assert_eq!(process.transmission_rate_bytes_per_second, 400);
        assert_eq!(process.reception_rate_bytes_per_second, 600);
        assert_eq!(process.peak_throughput_bytes_per_second, 1_000);
    }

    #[test]
    fn finalizing_a_tick_preserves_a_higher_process_peak() {
        let mut process = IpcProcessMetrics::new(42, String::from("worker"));
        process.temporal_transmission_accumulator = 100;
        process.temporal_reception_accumulator = 200;
        process.peak_throughput_bytes_per_second = 1_000;

        process.finalize_tick();

        assert_eq!(process.peak_throughput_bytes_per_second, 1_000);
    }
}
