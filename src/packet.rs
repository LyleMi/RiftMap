use std::net::Ipv4Addr;

// 60-byte IPv4/TCP SYN (including Linux-style options) plus Ethernet/FCS/preamble/IFG.
pub const SYN_WIRE_BYTES: u64 = 98;

const LINUX_EPHEMERAL_FIRST: u16 = 32768;
const LINUX_EPHEMERAL_LAST: u16 = 60999;

pub fn syn_cookie(
    secret: &[u8; 32],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
) -> u32 {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(&src.octets());
    h.update(&dst.octets());
    h.update(&source_port.to_be_bytes());
    h.update(&dest_port.to_be_bytes());
    u32::from_be_bytes(h.finalize().as_bytes()[..4].try_into().unwrap())
}
pub fn valid_ack(cookie: u32, ack: u32) -> bool {
    ack == cookie.wrapping_add(1)
}

pub fn ephemeral_source_port(
    secret: &[u8; 32],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dest_port: u16,
    nonce: u32,
) -> u16 {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(b"source-port");
    h.update(&src.octets());
    h.update(&dst.octets());
    h.update(&dest_port.to_be_bytes());
    h.update(&nonce.to_le_bytes());
    let sample = u16::from_be_bytes(h.finalize().as_bytes()[..2].try_into().unwrap());
    let span = LINUX_EPHEMERAL_LAST - LINUX_EPHEMERAL_FIRST + 1;
    LINUX_EPHEMERAL_FIRST + (sample % span)
}

pub fn timestamp_jitter(secret: &[u8; 32], dst: Ipv4Addr) -> u32 {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(b"ts-jitter");
    h.update(&dst.octets());
    let sample = u32::from_be_bytes(h.finalize().as_bytes()[..4].try_into().unwrap());
    sample % 5000
}

pub fn ip_identification(secret: &[u8; 32], src: Ipv4Addr, dst: Ipv4Addr, counter: u32) -> u16 {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(b"ip-id");
    h.update(&src.octets());
    h.update(&dst.octets());
    let base = u16::from_be_bytes(h.finalize().as_bytes()[..2].try_into().unwrap());
    base.wrapping_add(counter as u16)
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub struct SynPacket {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub source_port: u16,
    pub dest_port: u16,
    pub seq: u32,
    pub mss: u16,
    pub ttl: u8,
    pub window_size: u16,
    pub window_scale: u8,
    pub timestamp_value: u32,
    pub ip_id: u16,
}

impl SynPacket {
    pub fn encode(&self) -> Vec<u8> {
        // Linux-style SYN options: MSS, SACK permitted, timestamp, NOP, window scale.
        let options = [
            2,
            4,
            (self.mss >> 8) as u8,
            self.mss as u8,
            4,
            2,
            8,
            10,
            (self.timestamp_value >> 24) as u8,
            (self.timestamp_value >> 16) as u8,
            (self.timestamp_value >> 8) as u8,
            self.timestamp_value as u8,
            0,
            0,
            0,
            0,
            1,
            3,
            3,
            self.window_scale,
        ];
        let total = 20 + 20 + options.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
        p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        p[8] = self.ttl;
        p[9] = 6;
        p[12..16].copy_from_slice(&self.src.octets());
        p[16..20].copy_from_slice(&self.dst.octets());
        let ipcs = checksum(&p[..20]);
        p[10..12].copy_from_slice(&ipcs.to_be_bytes());
        let t = 20;
        p[t..t + 2].copy_from_slice(&self.source_port.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&self.dest_port.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&self.seq.to_be_bytes());
        p[t + 12] = (((20 + options.len()) / 4) as u8) << 4;
        p[t + 13] = 0x02;
        p[t + 14..t + 16].copy_from_slice(&self.window_size.to_be_bytes());
        p[t + 20..].copy_from_slice(&options);
        let mut pseudo = Vec::with_capacity(12 + total - 20);
        pseudo.extend_from_slice(&self.src.octets());
        pseudo.extend_from_slice(&self.dst.octets());
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((total - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..]);
        let tcpcs = checksum(&pseudo);
        p[t + 16..t + 18].copy_from_slice(&tcpcs.to_be_bytes());
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_checksums() {
        let p = SynPacket {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            source_port: 61000,
            dest_port: 22,
            seq: 7,
            mss: 1460,
            ttl: 64,
            window_size: 64240,
            window_scale: 7,
            timestamp_value: 1234,
            ip_id: 0xAB12,
        }
        .encode();
        assert_eq!(p.len(), 60);
        assert_eq!(p[8], 64);
        assert_eq!(u16::from_be_bytes(p[4..6].try_into().unwrap()), 0xAB12);
        assert_eq!(u16::from_be_bytes(p[34..36].try_into().unwrap()), 64240);
        assert_eq!(p[56], 1);
        assert_eq!(p[57], 3);
        assert_eq!(p[58], 3);
        assert_eq!(p[59], 7);
        assert_eq!(checksum(&p[..20]), 0);
        let mut ps = Vec::new();
        ps.extend_from_slice(&p[12..20]);
        ps.extend_from_slice(&[0, 6]);
        ps.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        ps.extend_from_slice(&p[20..]);
        assert_eq!(checksum(&ps), 0);
    }

    #[test]
    fn ephemeral_source_port_uses_linux_default_range() {
        let secret = [3; 32];
        let src = "192.0.2.1".parse().unwrap();
        let dst = "198.51.100.2".parse().unwrap();

        let port = ephemeral_source_port(&secret, src, dst, 22, 0);

        assert!((32768..=60999).contains(&port));
        assert_eq!(port, ephemeral_source_port(&secret, src, dst, 22, 0));
        // Different nonce produces different port
        assert_ne!(port, ephemeral_source_port(&secret, src, dst, 22, 1));
    }
    #[test]
    fn ack_wraps() {
        assert!(valid_ack(u32::MAX, 0));
    }
}
