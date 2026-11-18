//! Bounded, best-effort application name extraction.
//!
//! XDP sees individual packets, not TCP streams. These parsers therefore only
//! inspect a complete name in the current packet; they intentionally do not
//! attempt TCP reassembly in eBPF.

use aya_ebpf::programs::{TcContext, XdpContext};

use crate::parsing::{ptr_at, PORT_DNS, PORT_HTTP, PROTO_TCP, PROTO_UDP};

const NAME_CAPACITY: usize = 64;
const MAX_TLS_EXTENSIONS: usize = 16;
const MAX_SERVER_NAMES: usize = 8;
const MAX_DNS_LABELS: usize = 16;
const MAX_HTTP_SCAN: usize = 512;

trait PacketReader {
    fn byte_at(&self, offset: usize) -> Option<u8>;
}

struct XdpReader<'a> {
    ctx: &'a XdpContext,
}

impl PacketReader for XdpReader<'_> {
    #[inline(always)]
    fn byte_at(&self, offset: usize) -> Option<u8> {
        unsafe { ptr_at::<u8>(self.ctx, offset).ok().map(|ptr| *ptr) }
    }
}

struct TcReader<'a> {
    ctx: &'a TcContext,
}

impl PacketReader for TcReader<'_> {
    #[inline(always)]
    fn byte_at(&self, offset: usize) -> Option<u8> {
        self.ctx.load(offset).ok()
    }
}

#[inline(always)]
pub unsafe fn extract_xdp_hostname(
    ctx: &XdpContext,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    extract_hostname(&XdpReader { ctx }, protocol, dst_port, payload_off, output)
}

#[inline(always)]
pub fn extract_tc_hostname(
    ctx: &TcContext,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    extract_hostname(&TcReader { ctx }, protocol, dst_port, payload_off, output)
}

#[inline(always)]
fn add(offset: usize, length: usize) -> Option<usize> {
    offset.checked_add(length)
}

#[inline(always)]
fn u16_at<R: PacketReader>(reader: &R, offset: usize) -> Option<u16> {
    let hi = reader.byte_at(offset)?;
    let lo = reader.byte_at(add(offset, 1)?)?;
    Some(u16::from_be_bytes([hi, lo]))
}

#[inline(always)]
fn u24_at<R: PacketReader>(reader: &R, offset: usize) -> Option<usize> {
    let a = reader.byte_at(offset)? as usize;
    let b = reader.byte_at(add(offset, 1)?)? as usize;
    let c = reader.byte_at(add(offset, 2)?)? as usize;
    Some((a << 16) | (b << 8) | c)
}

#[inline(always)]
fn range_is_readable<R: PacketReader>(reader: &R, start: usize, end: usize) -> bool {
    start <= end && (start == end || reader.byte_at(end - 1).is_some())
}

#[inline(always)]
fn copy_name<R: PacketReader>(
    reader: &R,
    start: usize,
    length: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    if length == 0
        || length >= NAME_CAPACITY
        || !range_is_readable(reader, start, add(start, length).unwrap_or(0))
    {
        return false;
    }

    let mut i = 0;
    while i < length {
        if i >= NAME_CAPACITY - 1 {
            return false;
        }
        // The range was checked above. Falling back to zero can only occur if
        // packet data changed underneath us, which does not happen in either
        // BPF hook; it also keeps this path verifier-safe.
        output[i] = reader.byte_at(start + i).unwrap_or(0);
        i += 1;
    }
    true
}

#[inline(always)]
fn extract_hostname<R: PacketReader>(
    reader: &R,
    protocol: u8,
    dst_port: u16,
    payload_off: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    if protocol == PROTO_TCP && extract_tls_sni(reader, payload_off, output) {
        return true;
    }
    if protocol == PROTO_TCP && dst_port == PORT_HTTP {
        return extract_http_host(reader, payload_off, output);
    }
    if (protocol == PROTO_UDP || protocol == PROTO_TCP) && dst_port == PORT_DNS {
        return extract_dns_qname(reader, protocol, payload_off, output);
    }
    false
}

/// Extract a host_name from a TLS ClientHello server_name extension. TLS is
/// recognized by its record type instead of assuming it is always on port 443.
#[inline(always)]
fn extract_tls_sni<R: PacketReader>(
    reader: &R,
    payload: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    if reader.byte_at(payload) != Some(22)
        || reader.byte_at(add(payload, 1).unwrap_or(0)) != Some(3)
    {
        return false;
    }
    let record_len = match u16_at(reader, add(payload, 3).unwrap_or(0)) {
        Some(value) => value as usize,
        None => return false,
    };
    let record_end = match add(payload, 5).and_then(|start| add(start, record_len)) {
        Some(value) if range_is_readable(reader, payload, value) => value,
        _ => return false,
    };
    let handshake = match add(payload, 5) {
        Some(value) => value,
        None => return false,
    };
    if reader.byte_at(handshake) != Some(1) {
        return false;
    }
    let handshake_len = match u24_at(reader, add(handshake, 1).unwrap_or(0)) {
        Some(value) => value,
        None => return false,
    };
    let handshake_body = match add(handshake, 4) {
        Some(value) => value,
        None => return false,
    };
    let handshake_end = match add(handshake_body, handshake_len) {
        Some(value) if value <= record_end => value,
        _ => return false,
    };

    // legacy_version (2) + random (32) + session_id length.
    let mut offset = match add(handshake_body, 34) {
        Some(value) => value,
        None => return false,
    };
    let session_len = match reader.byte_at(offset) {
        Some(value) => value as usize,
        None => return false,
    };
    offset = match add(offset, 1 + session_len) {
        Some(value) if value <= handshake_end => value,
        _ => return false,
    };
    let cipher_len = match u16_at(reader, offset) {
        Some(value) => value as usize,
        None => return false,
    };
    offset = match add(offset, 2 + cipher_len) {
        Some(value) if value <= handshake_end => value,
        _ => return false,
    };
    let compression_len = match reader.byte_at(offset) {
        Some(value) => value as usize,
        None => return false,
    };
    offset = match add(offset, 1 + compression_len) {
        Some(value) if value <= handshake_end => value,
        _ => return false,
    };
    let extensions_len = match u16_at(reader, offset) {
        Some(value) => value as usize,
        None => return false,
    };
    offset = match add(offset, 2) {
        Some(value) => value,
        None => return false,
    };
    let extensions_end = match add(offset, extensions_len) {
        Some(value) if value <= handshake_end => value,
        _ => return false,
    };

    let mut extension_count = 0;
    while offset < extensions_end && extension_count < MAX_TLS_EXTENSIONS {
        let extension_type = match u16_at(reader, offset) {
            Some(value) => value,
            None => return false,
        };
        let extension_len = match u16_at(reader, add(offset, 2).unwrap_or(0)) {
            Some(value) => value as usize,
            None => return false,
        };
        let extension_data = match add(offset, 4) {
            Some(value) => value,
            None => return false,
        };
        let next_extension = match add(extension_data, extension_len) {
            Some(value) if value <= extensions_end => value,
            _ => return false,
        };
        if extension_type == 0
            && extract_server_name_list(reader, extension_data, next_extension, output)
        {
            return true;
        }
        offset = next_extension;
        extension_count += 1;
    }
    false
}

#[inline(always)]
fn extract_server_name_list<R: PacketReader>(
    reader: &R,
    data_start: usize,
    data_end: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    let list_len = match u16_at(reader, data_start) {
        Some(value) => value as usize,
        None => return false,
    };
    let mut offset = match add(data_start, 2) {
        Some(value) => value,
        None => return false,
    };
    let list_end = match add(offset, list_len) {
        Some(value) if value <= data_end => value,
        _ => return false,
    };

    let mut name_count = 0;
    while offset < list_end && name_count < MAX_SERVER_NAMES {
        let name_type = match reader.byte_at(offset) {
            Some(value) => value,
            None => return false,
        };
        let name_len = match u16_at(reader, add(offset, 1).unwrap_or(0)) {
            Some(value) => value as usize,
            None => return false,
        };
        let name_start = match add(offset, 3) {
            Some(value) => value,
            None => return false,
        };
        let next_name = match add(name_start, name_len) {
            Some(value) if value <= list_end => value,
            _ => return false,
        };
        if name_type == 0 {
            return copy_name(reader, name_start, name_len, output);
        }
        offset = next_name;
        name_count += 1;
    }
    false
}

#[inline(always)]
fn extract_http_host<R: PacketReader>(
    reader: &R,
    payload: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    let mut offset = payload;
    let mut line_start = true;
    let mut scanned = 0;
    while scanned < MAX_HTTP_SCAN {
        let byte = match reader.byte_at(offset) {
            Some(value) => value,
            None => return false,
        };
        if line_start && matches_host_header(reader, offset) {
            let mut value_start = match add(offset, 5) {
                Some(value) => value,
                None => return false,
            };
            while matches!(reader.byte_at(value_start), Some(b' ' | b'\t')) {
                value_start += 1;
            }
            let mut value_end = value_start;
            let mut value_len = 0;
            while value_len < NAME_CAPACITY - 1 {
                match reader.byte_at(value_end) {
                    Some(b'\r' | b'\n' | b' ' | b'\t') => break,
                    Some(_) => {
                        value_end += 1;
                        value_len += 1;
                    }
                    None => return false,
                }
            }
            return value_end > value_start
                && copy_name(reader, value_start, value_end - value_start, output);
        }
        line_start = byte == b'\n';
        offset += 1;
        scanned += 1;
    }
    false
}

#[inline(always)]
fn matches_host_header<R: PacketReader>(reader: &R, offset: usize) -> bool {
    matches!(reader.byte_at(offset), Some(b'h' | b'H'))
        && matches!(
            reader.byte_at(add(offset, 1).unwrap_or(0)),
            Some(b'o' | b'O')
        )
        && matches!(
            reader.byte_at(add(offset, 2).unwrap_or(0)),
            Some(b's' | b'S')
        )
        && matches!(
            reader.byte_at(add(offset, 3).unwrap_or(0)),
            Some(b't' | b'T')
        )
        && reader.byte_at(add(offset, 4).unwrap_or(0)) == Some(b':')
}

#[inline(always)]
fn extract_dns_qname<R: PacketReader>(
    reader: &R,
    protocol: u8,
    payload: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    // TCP DNS prefixes the DNS message with its two-byte length field.
    let dns = if protocol == PROTO_TCP {
        match add(payload, 2) {
            Some(value) => value,
            None => return false,
        }
    } else {
        payload
    };
    let qname = match add(dns, 12) {
        Some(value) => value,
        None => return false,
    };
    let name_len = match dns_name_length(reader, qname) {
        Some(value) => value,
        None => return false,
    };
    copy_dns_name(reader, qname, name_len, output)
}

/// Returns the printable name length. Compression is deliberately rejected:
/// standard client queries do not need it, and accepting it would require a
/// pointer-following parser with more verifier state.
#[inline(always)]
fn dns_name_length<R: PacketReader>(reader: &R, mut offset: usize) -> Option<usize> {
    let mut labels = 0;
    let mut total = 0;
    loop {
        if labels >= MAX_DNS_LABELS {
            return None;
        }
        let label_len = reader.byte_at(offset)? as usize;
        if label_len == 0 {
            return (total > 0).then_some(total);
        }
        if label_len > 63 || (label_len & 0xc0) != 0 {
            return None;
        }
        let label_start = add(offset, 1)?;
        let label_end = add(label_start, label_len)?;
        if !range_is_readable(reader, label_start, label_end) {
            return None;
        }
        total = add(total, label_len)?;
        if labels > 0 {
            total = add(total, 1)?;
        }
        if total >= NAME_CAPACITY {
            return None;
        }
        offset = label_end;
        labels += 1;
    }
}

#[inline(always)]
fn copy_dns_name<R: PacketReader>(
    reader: &R,
    mut offset: usize,
    expected_len: usize,
    output: &mut [u8; NAME_CAPACITY],
) -> bool {
    let mut labels = 0;
    let mut written = 0;
    loop {
        if labels >= MAX_DNS_LABELS {
            return false;
        }
        let label_len = match reader.byte_at(offset) {
            Some(value) => value as usize,
            None => return false,
        };
        if label_len == 0 {
            return written == expected_len;
        }
        let label_start = match add(offset, 1) {
            Some(value) => value,
            None => return false,
        };
        if labels > 0 {
            if written >= NAME_CAPACITY - 1 {
                return false;
            }
            output[written] = b'.';
            written += 1;
        }
        let mut i = 0;
        while i < label_len {
            if written >= NAME_CAPACITY - 1 {
                return false;
            }
            output[written] = match reader.byte_at(label_start + i) {
                Some(value) => value,
                None => return false,
            };
            written += 1;
            i += 1;
        }
        offset = match add(label_start, label_len) {
            Some(value) => value,
            None => return false,
        };
        labels += 1;
    }
}
