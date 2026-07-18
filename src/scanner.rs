use crate::{Config, job::PreparedJob, packet::SYN_WIRE_BYTES, permutation::Permutation};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
#[cfg(target_os = "linux")]
use {
    base64::Engine,
    std::{path::Path, process::Command, sync::Arc, time::Duration},
};

pub fn resolve_source_ip(cfg: &Config) -> anyhow::Result<Ipv4Addr> {
    if let Some(ip) = cfg.network.source_ip.address() {
        return Ok(ip);
    }
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect("1.1.1.1:53")?;
    match s.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => anyhow::bail!("route selected a non-IPv4 source"),
    }
}
pub fn estimate(cfg: &Config, count: u64) -> Estimate {
    let packets = count.saturating_mul(cfg.scan.syn_attempts as u64);
    let bytes = packets.saturating_mul(SYN_WIRE_BYTES);
    let bps = cfg.network.provider_egress_mbps * 1_000_000.0 / 8.0 * cfg.network.application_ratio;
    Estimate {
        targets: count,
        worst_packets: packets,
        estimated_wire_bytes: bytes,
        minimum_seconds: bytes as f64 / bps,
    }
}
#[derive(Debug)]
pub struct Estimate {
    pub targets: u64,
    pub worst_packets: u64,
    pub estimated_wire_bytes: u64,
    pub minimum_seconds: f64,
}

pub fn dry_run(job: &PreparedJob) -> anyhow::Result<String> {
    use memmap2::Mmap;
    use std::fs::File;
    let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
    let p = Permutation::new(job.meta.target_count, seed)?;
    let file = File::open(job.dir.join("targets.bin"))?;
    let targets = unsafe { Mmap::map(&file)? };
    let mut h = blake3::Hasher::new();
    for i in 0..job.meta.target_count {
        let index = p.get(i) as usize;
        h.update(&targets[index * 4..index * 4 + 4]);
    }
    Ok(h.finalize().to_hex().to_string())
}

pub fn doctor(cfg: &Config) -> anyhow::Result<Vec<String>> {
    let mut checks = vec![
        format!("source IPv4: {}", resolve_source_ip(cfg)?),
        format!("interface: {}", cfg.network.interface),
    ];
    let listener = std::net::TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        cfg.scan.source_port,
    ))
    .map_err(|e| anyhow::anyhow!("source port {} unavailable: {e}", cfg.scan.source_port))?;
    drop(listener);
    checks.push(format!("source port {}: available", cfg.scan.source_port));
    #[cfg(target_os = "linux")]
    {
        let privileged = unsafe { libc::geteuid() } == 0 || linux_capabilities_ok()?;
        anyhow::ensure!(privileged, "root or CAP_NET_RAW/CAP_NET_ADMIN is required");
        pcap::Capture::from_device(cfg.network.interface.as_str())?
            .open()
            .map_err(|e| anyhow::anyhow!("libpcap/interface: {e}"))?;
        checks.push("libpcap capture: ok".into());
        if cfg.network.require_tc {
            verify_tc(cfg)?;
            checks.push("tc root qdisc: verified".into());
        }
    }
    #[cfg(not(target_os = "linux"))]
    checks.push("network scan: unsupported on this OS (Linux required)".into());
    Ok(checks)
}

#[cfg(target_os = "linux")]
fn linux_capabilities_ok() -> anyhow::Result<bool> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .ok_or_else(|| anyhow::anyhow!("CapEff missing from /proc/self/status"))?;
    let bits = u64::from_str_radix(effective.trim(), 16)?;
    Ok(bits & (1 << 12) != 0 && bits & (1 << 13) != 0)
}

pub fn tc_template(cfg: &Config) -> String {
    let mbps = cfg.network.provider_egress_mbps * cfg.network.tc_ratio;
    format!(
        "# Save the current qdisc before applying\ntc -j qdisc show dev {i} > riftmap-qdisc-backup.json\n# Apply the whole-interface hard ceiling ({r:.3} Mbit/s)\ntc qdisc replace dev {i} root tbf rate {r:.3}mbit burst 256kb latency 50ms\n# Verify\ntc -s -j qdisc show dev {i}\n# Restore (typical default; inspect the saved JSON first)\ntc qdisc replace dev {i} root fq_codel\n",
        i = cfg.network.interface,
        r = mbps
    )
}

#[cfg(target_os = "linux")]
fn verify_tc(cfg: &Config) -> anyhow::Result<()> {
    let out = Command::new("tc")
        .args(["-j", "qdisc", "show", "dev", &cfg.network.interface])
        .output()?;
    anyhow::ensure!(out.status.success(), "tc query failed");
    let qdiscs: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let root = qdiscs
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|q| q.get("root").and_then(|v| v.as_bool()) == Some(true))
        })
        .ok_or_else(|| anyhow::anyhow!("root qdisc not found"))?;
    anyhow::ensure!(
        root.get("kind").and_then(|v| v.as_str()) == Some("tbf"),
        "root qdisc is not tbf"
    );
    let rate = root
        .get("options")
        .and_then(|v| v.get("rate"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("tc did not report a numeric TBF rate"))?;
    let ceiling =
        (cfg.network.provider_egress_mbps * 1_000_000.0 / 8.0 * cfg.network.tc_ratio) as u64;
    anyhow::ensure!(
        rate <= ceiling,
        "TBF rate {rate} B/s exceeds configured ceiling {ceiling} B/s"
    );
    Ok(())
}

pub fn scan(job: &mut PreparedJob, cfg: &Config) -> anyhow::Result<ScanSummary> {
    #[cfg(target_os = "linux")]
    {
        linux::run(job, cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (job, cfg);
        anyhow::bail!("live scanning is supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
async fn banner_pipeline(
    job_dir: &Path,
    targets: Vec<Ipv4Addr>,
    source_ip: Ipv4Addr,
    cfg: &Config,
    scan_id: &str,
) -> anyhow::Result<()> {
    use tokio::{io::AsyncReadExt, net::TcpSocket, sync::Semaphore, task::JoinSet, time};
    let sem = Arc::new(Semaphore::new(cfg.scan.banner_concurrency));
    let mut ticker = time::interval(Duration::from_secs_f64(
        1.0 / f64::from(cfg.scan.banner_connects_per_second.max(1)),
    ));
    let mut tasks = JoinSet::new();
    for ip in targets {
        ticker.tick().await;
        let permit = sem.clone().acquire_owned().await?;
        let scan = cfg.scan.clone();
        let scan_id = scan_id.to_owned();
        tasks.spawn(async move {
            let _permit = permit;
            time::sleep(Duration::from_millis(250)).await;
            let mut last_status = crate::BannerStatus::ConnectFailed;
            let mut evidence = Vec::new();
            for _ in 0..scan.banner_attempts {
                let socket = TcpSocket::new_v4()?;
                socket.bind(SocketAddrV4::new(source_ip, 0).into())?;
                let connected = time::timeout(
                    Duration::from_millis(scan.connect_timeout_ms),
                    socket.connect(SocketAddrV4::new(ip, scan.port).into()),
                )
                .await;
                let mut stream = match connected {
                    Ok(Ok(s)) => s,
                    Ok(Err(_)) => {
                        last_status = crate::BannerStatus::ConnectFailed;
                        continue;
                    }
                    Err(_) => {
                        last_status = crate::BannerStatus::Timeout;
                        continue;
                    }
                };
                evidence.clear();
                loop {
                    match crate::protocol::message_len(
                        scan.protocol,
                        &evidence,
                        scan.banner_max_bytes,
                    ) {
                        Ok(Some(n)) => {
                            evidence.truncate(n);
                            break;
                        }
                        Err(s) => {
                            last_status = s;
                            break;
                        }
                        Ok(None) => {}
                    }
                    let mut chunk = [0u8; 1024];
                    match time::timeout(
                        Duration::from_millis(scan.banner_timeout_ms),
                        stream.read(&mut chunk),
                    )
                    .await
                    {
                        Ok(Ok(0)) => {
                            last_status = crate::BannerStatus::ProtocolMismatch;
                            break;
                        }
                        Ok(Ok(n)) => {
                            evidence.extend_from_slice(&chunk[..n]);
                            if evidence.len() > scan.banner_max_bytes {
                                last_status = crate::BannerStatus::Oversized;
                                break;
                            }
                        }
                        Ok(Err(_)) => {
                            last_status = crate::BannerStatus::ConnectFailed;
                            break;
                        }
                        Err(_) => {
                            last_status = crate::BannerStatus::Timeout;
                            break;
                        }
                    }
                }
                if let Ok(Some(_)) =
                    crate::protocol::message_len(scan.protocol, &evidence, scan.banner_max_bytes)
                {
                    return match crate::protocol::parse(scan.protocol, &evidence) {
                        Ok(p) => Ok::<_, anyhow::Error>(make_result(
                            &scan_id,
                            ip,
                            &scan,
                            evidence,
                            crate::BannerStatus::Ok,
                            Some(p),
                        )),
                        Err(s) => Ok(make_result(&scan_id, ip, &scan, evidence, s, None)),
                    };
                }
                if matches!(
                    last_status,
                    crate::BannerStatus::ProtocolMismatch | crate::BannerStatus::Oversized
                ) {
                    break;
                }
            }
            Ok(make_result(
                &scan_id,
                ip,
                &scan,
                evidence,
                last_status,
                None,
            ))
        });
    }
    while let Some(result) = tasks.join_next().await {
        crate::job::append_event(job_dir, &result??)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn make_result(
    scan_id: &str,
    ip: Ipv4Addr,
    scan: &crate::config::ScanConfig,
    raw: Vec<u8>,
    status: crate::BannerStatus,
    parsed: Option<crate::protocol::ParsedBanner>,
) -> crate::ResultV1 {
    let observed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    let parsed = parsed.unwrap_or_default();
    crate::ResultV1 {
        schema_version: crate::SCHEMA_VERSION,
        result_id: crate::result::result_id(scan_id, ip, scan.port),
        scan_id: scan_id.into(),
        ip,
        port: scan.port,
        protocol: scan.protocol,
        state: crate::TargetState::Open,
        syn_attempts: 0,
        rtt_ms: None,
        first_observed_at: Some(observed.clone()),
        last_observed_at: Some(observed),
        banner_status: Some(status),
        banner_base64: (!raw.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&raw)),
        banner_text: parsed.text,
        ssh: parsed.ssh,
        ftp: parsed.ftp,
        mysql: parsed.mysql,
    }
}
#[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ScanSummary {
    pub completed: bool,
    pub sent: u64,
    pub open: u64,
    pub closed: u64,
    pub unreachable: u64,
    pub no_response: u64,
    pub pcap_drops: u64,
}

fn final_checkpoint_index(completed: bool, target_count: u64, next_index: u64) -> u64 {
    if completed { target_count } else { next_index }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{packet, rate::TokenBucket};
    use memmap2::Mmap;
    use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
    use std::{
        fs::File,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Instant,
    };
    fn find_index(targets: &[u8], ip: Ipv4Addr) -> Option<usize> {
        let needle = u32::from(ip);
        let n = targets.len() / 4;
        let mut lo = 0;
        let mut hi = n;
        while lo < hi {
            let m = (lo + hi) / 2;
            let v = u32::from_be_bytes(targets[m * 4..m * 4 + 4].try_into().unwrap());
            if v < needle { lo = m + 1 } else { hi = m }
        }
        (lo < n && targets[lo * 4..lo * 4 + 4] == needle.to_be_bytes()).then_some(lo)
    }
    fn receive(
        cap: &mut pcap::Capture<pcap::Active>,
        states: &mut [u8],
        targets: &[u8],
        secret: &[u8; 32],
        src: Ipv4Addr,
        cfg: &Config,
    ) {
        while let Ok(pkt) = cap.next_packet() {
            let d = pkt.data;
            let o = if d.first().map(|b| b >> 4) == Some(4) {
                0
            } else {
                14
            };
            if d.len() < o + 40 || d[o] >> 4 != 4 {
                continue;
            }
            let ihl = ((d[o] & 15) as usize) * 4;
            let proto = d[o + 9];
            if proto == 6 && d.len() >= o + ihl + 20 {
                let remote = Ipv4Addr::new(d[o + 12], d[o + 13], d[o + 14], d[o + 15]);
                let t = o + ihl;
                let sp = u16::from_be_bytes([d[t], d[t + 1]]);
                let dp = u16::from_be_bytes([d[t + 2], d[t + 3]]);
                let ack = u32::from_be_bytes(d[t + 8..t + 12].try_into().unwrap());
                if sp != cfg.scan.port
                    || dp != cfg.scan.source_port
                    || !packet::valid_ack(
                        packet::syn_cookie(
                            secret,
                            src,
                            remote,
                            cfg.scan.source_port,
                            cfg.scan.port,
                        ),
                        ack,
                    )
                {
                    continue;
                }
                if let Some(i) = find_index(targets, remote) {
                    let flags = d[t + 13];
                    if flags & 0x12 == 0x12 {
                        states[i] = 3
                    } else if flags & 0x04 != 0 && states[i] < 2 {
                        states[i] = 2
                    }
                }
            } else if proto == 1 {
                let icmp = o + ihl;
                if d.len() < icmp + 8 + 20 || !matches!(d[icmp], 3 | 11) {
                    continue;
                }
                let inner = icmp + 8;
                if d[inner] >> 4 != 4 {
                    continue;
                }
                let inner_ihl = ((d[inner] & 15) as usize) * 4;
                if d.len() < inner + inner_ihl + 8 || d[inner + 9] != 6 {
                    continue;
                }
                let inner_src =
                    Ipv4Addr::new(d[inner + 12], d[inner + 13], d[inner + 14], d[inner + 15]);
                let remote =
                    Ipv4Addr::new(d[inner + 16], d[inner + 17], d[inner + 18], d[inner + 19]);
                let tcp = inner + inner_ihl;
                let source_port = u16::from_be_bytes([d[tcp], d[tcp + 1]]);
                let dest_port = u16::from_be_bytes([d[tcp + 2], d[tcp + 3]]);
                let seq = u32::from_be_bytes(d[tcp + 4..tcp + 8].try_into().unwrap());
                if inner_src != src
                    || source_port != cfg.scan.source_port
                    || dest_port != cfg.scan.port
                    || seq != packet::syn_cookie(secret, src, remote, source_port, dest_port)
                {
                    continue;
                }
                if let Some(i) = find_index(targets, remote) {
                    if states[i] < 1 {
                        states[i] = 1
                    }
                }
            }
        }
    }
    pub fn run(job: &mut PreparedJob, cfg: &Config) -> anyhow::Result<ScanSummary> {
        let src = resolve_source_ip(cfg)?;
        if cfg.network.require_tc {
            verify_tc(cfg)?;
        }
        let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
        let perm = Permutation::new(job.meta.target_count, seed)?;
        let mut cap = pcap::Capture::from_device(cfg.network.interface.as_str())?
            .promisc(false)
            .immediate_mode(true)
            .timeout(1)
            .open()?;
        cap.filter(
            &format!(
                "(tcp src port {} and dst port {}) or icmp",
                cfg.scan.port, cfg.scan.source_port
            ),
            true,
        )?;
        cap = cap.setnonblock()?;
        let raw = Socket::new(Domain::IPV4, Type::RAW, Some(SockProtocol::TCP))?;
        raw.set_header_included_v4(true)?;
        raw.bind_device(Some(cfg.network.interface.as_bytes()))?;
        let target_file = File::open(job.dir.join("targets.bin"))?;
        let targets = unsafe { Mmap::map(&target_file)? };
        let mut states = job.states()?;
        let rate =
            cfg.network.provider_egress_mbps * 1_000_000.0 / 8.0 * cfg.network.application_ratio;
        let mut bucket = TokenBucket::new(rate, 0.1);
        let start = Instant::now();
        let stopping = Arc::new(AtomicBool::new(false));
        let signal = stopping.clone();
        ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
        'rounds: for round in job.meta.round..cfg.scan.syn_attempts {
            let start_order = if round == job.meta.round {
                job.meta.next_index
            } else {
                0
            };
            job.meta.round = round;
            for order in start_order..job.meta.target_count {
                if stopping.load(Ordering::SeqCst) {
                    job.checkpoint(order)?;
                    break 'rounds;
                }
                let idx = perm.get(order) as usize;
                if states[idx] != 0 {
                    continue;
                }
                let ip = Ipv4Addr::from(u32::from_be_bytes(
                    targets[idx * 4..idx * 4 + 4].try_into().unwrap(),
                ));
                let wait = bucket.consume_at(packet::SYN_WIRE_BYTES, start.elapsed().as_secs_f64());
                if !wait.is_zero() {
                    thread::sleep(wait);
                }
                let seq = packet::syn_cookie(&seed, src, ip, cfg.scan.source_port, cfg.scan.port);
                let p = packet::build_syn(src, ip, cfg.scan.source_port, cfg.scan.port, seq, 1460);
                raw.send_to(&p, &SocketAddrV4::new(ip, cfg.scan.port).into())?;
                job.meta.packets_sent = job.meta.packets_sent.saturating_add(1);
                receive(&mut cap, &mut states, &targets, &seed, src, cfg);
                // Persist periodically; an atomic fsync per target makes large
                // scans unusable. Ctrl+C always writes the exact next index.
                if (order + 1) % 10_000 == 0 {
                    job.checkpoint(order + 1)?;
                }
            }
            job.meta.round = round + 1;
            job.checkpoint(0)?;
            if round + 1 < cfg.scan.syn_attempts {
                thread::sleep(Duration::from_secs(1));
                receive(&mut cap, &mut states, &targets, &seed, src, cfg);
            }
        }
        thread::sleep(Duration::from_secs(1));
        receive(&mut cap, &mut states, &targets, &seed, src, cfg);
        states.flush()?;
        let stats = cap.stats()?;
        let run_drops = u64::from(stats.dropped) + u64::from(stats.if_dropped);
        job.meta.pcap_drops = job.meta.pcap_drops.saturating_add(run_drops);
        job.meta.degraded |= run_drops > 0;
        let completed = job.meta.round >= cfg.scan.syn_attempts;
        let next_index =
            final_checkpoint_index(completed, job.meta.target_count, job.meta.next_index);
        job.checkpoint(next_index)?;
        let mut s = ScanSummary {
            completed,
            sent: job.meta.packets_sent,
            pcap_drops: job.meta.pcap_drops,
            ..Default::default()
        };
        for &v in states.iter() {
            match v {
                3 => s.open += 1,
                2 => s.closed += 1,
                1 => s.unreachable += 1,
                _ => s.no_response += 1,
            }
        }
        let open_targets = (0..states.len())
            .filter(|&i| states[i] == 3)
            .map(|i| {
                Ipv4Addr::from(u32::from_be_bytes(
                    targets[i * 4..i * 4 + 4].try_into().unwrap(),
                ))
            })
            .collect();
        drop(states);
        drop(targets);
        crate::job::save_summary(&job.dir, &s)?;
        tokio::runtime::Runtime::new()?.block_on(banner_pipeline(
            &job.dir,
            open_targets,
            src,
            cfg,
            &job.meta.scan_id,
        ))?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::final_checkpoint_index;

    #[test]
    fn interrupted_scan_preserves_resume_index() {
        assert_eq!(final_checkpoint_index(false, 100, 37), 37);
        assert_eq!(final_checkpoint_index(true, 100, 0), 100);
    }
}
