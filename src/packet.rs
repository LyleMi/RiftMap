use std::net::Ipv4Addr;

// 52-byte IPv4/TCP SYN (including options) plus Ethernet/FCS/preamble/IFG.
pub const SYN_WIRE_BYTES: u64 = 90;

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

pub fn build_syn(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    seq: u32,
    mss: u16,
) -> Vec<u8> {
    // MSS, SACK permitted, NOP, window scale 8; padded to a 32-byte TCP header.
    let options = [2, 4, (mss >> 8) as u8, mss as u8, 4, 2, 1, 3, 3, 8, 1, 1];
    let total = 20 + 20 + options.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ipcs = checksum(&p[..20]);
    p[10..12].copy_from_slice(&ipcs.to_be_bytes());
    let t = 20;
    p[t..t + 2].copy_from_slice(&source_port.to_be_bytes());
    p[t + 2..t + 4].copy_from_slice(&dest_port.to_be_bytes());
    p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    p[t + 12] = (((20 + options.len()) / 4) as u8) << 4;
    p[t + 13] = 0x02;
    p[t + 14..t + 16].copy_from_slice(&64240u16.to_be_bytes());
    p[t + 20..].copy_from_slice(&options);
    let mut pseudo = Vec::with_capacity(12 + total - 20);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&((total - 20) as u16).to_be_bytes());
    pseudo.extend_from_slice(&p[20..]);
    let tcpcs = checksum(&pseudo);
    p[t + 16..t + 18].copy_from_slice(&tcpcs.to_be_bytes());
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_checksums() {
        let p = build_syn(
            "192.0.2.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            61000,
            22,
            7,
            1460,
        );
        assert_eq!(checksum(&p[..20]), 0);
        let mut ps = Vec::new();
        ps.extend_from_slice(&p[12..20]);
        ps.extend_from_slice(&[0, 6]);
        ps.extend_from_slice(&((p.len() - 20) as u16).to_be_bytes());
        ps.extend_from_slice(&p[20..]);
        assert_eq!(checksum(&ps), 0);
    }
    #[test]
    fn ack_wraps() {
        assert!(valid_ack(u32::MAX, 0));
    }
}
