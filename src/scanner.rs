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

async fn banner_pipeline(
    job_dir: &Path,
    targets: Vec<Ipv4Addr>,
    source_ip: Ipv4Addr,
    cfg: &Config,
    scan_id: &str,
) -> anyhow::Result<()> {
    use tokio::{sync::Semaphore, task::JoinSet, time};
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
            inspect_banner(&scan_id, ip, source_ip, &scan).await
        });
    }
    while let Some(result) = tasks.join_next().await {
        crate::job::append_event(job_dir, &result??)?;
    }
    Ok(())
}

struct BannerObservation {
    raw: Vec<u8>,
    status: crate::BannerStatus,
    parsed: Option<crate::protocol::ParsedBanner>,
}

async fn inspect_banner(
    scan_id: &str,
    ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    scan: &crate::config::ScanConfig,
) -> anyhow::Result<crate::ResultV1> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut observation = BannerObservation {
        raw: Vec::new(),
        status: crate::BannerStatus::ConnectFailed,
        parsed: None,
    };
    for _ in 0..scan.banner_attempts {
        let mut stream = match connect_banner(ip, source_ip, scan).await? {
            Ok(stream) => stream,
            Err(status) => {
                observation.status = status;
                continue;
            }
        };
        observation.raw.clear();
        observation.status = read_banner(&mut stream, scan, &mut observation.raw).await;
        if observation.status == crate::BannerStatus::Ok {
            match crate::protocol::parse(scan.protocol, &observation.raw) {
                Ok(parsed) => observation.parsed = Some(parsed),
                Err(status) => observation.status = status,
            }
            break;
        }
        if terminal_banner_status(observation.status) {
            break;
        }
    }
    Ok(make_result(scan_id, ip, scan, observation))
}

async fn connect_banner(
    ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    scan: &crate::config::ScanConfig,
) -> anyhow::Result<Result<tokio::net::TcpStream, crate::BannerStatus>> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddrV4::new(source_ip, 0).into())?;
    let connected = tokio::time::timeout(
        Duration::from_millis(scan.connect_timeout_ms),
        socket.connect(SocketAddrV4::new(ip, scan.port).into()),
    )
    .await;
    Ok(match connected {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(crate::BannerStatus::ConnectFailed),
        Err(_) => Err(crate::BannerStatus::Timeout),
    })
}

async fn read_banner(
    stream: &mut tokio::net::TcpStream,
    scan: &crate::config::ScanConfig,
    evidence: &mut Vec<u8>,
) -> crate::BannerStatus {
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(status) = banner_completion(scan, evidence) {
            return status;
        }
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout(
            Duration::from_millis(scan.banner_timeout_ms),
            stream.read(&mut chunk),
        )
        .await;
        match read {
            Ok(Ok(0)) => return crate::BannerStatus::ProtocolMismatch,
            Ok(Ok(n)) => evidence.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return crate::BannerStatus::ConnectFailed,
            Err(_) => return crate::BannerStatus::Timeout,
        }
    }
}

fn banner_completion(
    scan: &crate::config::ScanConfig,
    evidence: &mut Vec<u8>,
) -> Option<crate::BannerStatus> {
    match crate::protocol::message_len(scan.protocol, evidence, scan.banner_max_bytes) {
        Ok(Some(length)) => {
            evidence.truncate(length);
            Some(crate::BannerStatus::Ok)
        }
        Ok(None) => None,
        Err(status) => Some(status),
    }
}

fn terminal_banner_status(status: crate::BannerStatus) -> bool {
    matches!(
        status,
        crate::BannerStatus::ProtocolMismatch | crate::BannerStatus::Oversized
    )
}

fn make_result(
    scan_id: &str,
    ip: Ipv4Addr,
    scan: &crate::config::ScanConfig,
    observation: BannerObservation,
) -> crate::ResultV1 {
    let observed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string();
    let parsed = observation.parsed.unwrap_or_default();
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
        banner_status: Some(observation.status),
        banner_base64: (!observation.raw.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&observation.raw)),
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
    struct ReplyContext<'a> {
        states: &'a mut [u8],
        targets: &'a [u8],
        secret: &'a [u8; 32],
        src: Ipv4Addr,
        scan: &'a crate::config::ScanConfig,
    }

    fn receive(cap: &mut pcap::Capture<pcap::Active>, context: &mut ReplyContext<'_>) {
        while let Ok(pkt) = cap.next_packet() {
            let Some((offset, ihl, protocol)) = ipv4_header(pkt.data) else {
                continue;
            };
            match protocol {
                6 => handle_tcp_reply(pkt.data, offset, ihl, context),
                1 => handle_icmp_reply(pkt.data, offset, ihl, context),
                _ => {}
            }
        }
    }

    struct InnerTcpReply {
        remote: Ipv4Addr,
        source_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        sequence: u32,
    }

    fn ipv4_header(data: &[u8]) -> Option<(usize, usize, u8)> {
        if data.first().map(|byte| byte >> 4) == Some(4) {
            return parse_ipv4_header(data, 0);
        }
        if data.len() >= 14 && data[12..14] == [0x08, 0x00] {
            return parse_ipv4_header(data, 14);
        }
        if data.len() >= 16 && data[14..16] == [0x08, 0x00] {
            return parse_ipv4_header(data, 16);
        }
        None
    }

    fn parse_ipv4_header(data: &[u8], offset: usize) -> Option<(usize, usize, u8)> {
        if data.len() < offset + 20 || data[offset] >> 4 != 4 {
            return None;
        }
        let ihl = ((data[offset] & 15) as usize) * 4;
        (ihl >= 20 && data.len() >= offset + ihl).then_some((offset, ihl, data[offset + 9]))
    }

    fn handle_tcp_reply(data: &[u8], offset: usize, ihl: usize, context: &mut ReplyContext<'_>) {
        let tcp = offset + ihl;
        if data.len() < tcp + 20 {
            return;
        }
        let remote = ipv4_at(data, offset + 12);
        let source_port = u16::from_be_bytes([data[tcp], data[tcp + 1]]);
        let dest_port = u16::from_be_bytes([data[tcp + 2], data[tcp + 3]]);
        let ack = u32::from_be_bytes(data[tcp + 8..tcp + 12].try_into().unwrap());
        let cookie = packet::syn_cookie(
            context.secret,
            context.src,
            remote,
            context.scan.source_port,
            context.scan.port,
        );
        if source_port != context.scan.port
            || dest_port != context.scan.source_port
            || !packet::valid_ack(cookie, ack)
        {
            return;
        }
        let Some(index) = find_index(context.targets, remote) else {
            return;
        };
        let flags = data[tcp + 13];
        if flags & 0x12 == 0x12 {
            context.states[index] = 3;
        } else if flags & 0x04 != 0 && context.states[index] < 2 {
            context.states[index] = 2;
        }
    }

    fn handle_icmp_reply(data: &[u8], offset: usize, ihl: usize, context: &mut ReplyContext<'_>) {
        let icmp = offset + ihl;
        if data.len() < icmp + 28 || !matches!(data[icmp], 3 | 11) {
            return;
        }
        let Some(reply) = inner_tcp_reply(data, icmp + 8) else {
            return;
        };
        if !valid_inner_reply(&reply, context) {
            return;
        }
        if let Some(index) = find_index(context.targets, reply.remote) {
            context.states[index] = context.states[index].max(1);
        }
    }

    fn inner_tcp_reply(data: &[u8], inner: usize) -> Option<InnerTcpReply> {
        let inner_ihl = ((data[inner] & 15) as usize) * 4;
        if data[inner] >> 4 != 4
            || inner_ihl < 20
            || data.len() < inner + inner_ihl + 8
            || data[inner + 9] != 6
        {
            return None;
        }
        let tcp = inner + inner_ihl;
        Some(InnerTcpReply {
            source_ip: ipv4_at(data, inner + 12),
            remote: ipv4_at(data, inner + 16),
            source_port: u16::from_be_bytes([data[tcp], data[tcp + 1]]),
            dest_port: u16::from_be_bytes([data[tcp + 2], data[tcp + 3]]),
            sequence: u32::from_be_bytes(data[tcp + 4..tcp + 8].try_into().unwrap()),
        })
    }

    fn valid_inner_reply(reply: &InnerTcpReply, context: &ReplyContext<'_>) -> bool {
        let cookie = packet::syn_cookie(
            context.secret,
            context.src,
            reply.remote,
            reply.source_port,
            reply.dest_port,
        );
        reply.source_ip == context.src
            && reply.source_port == context.scan.source_port
            && reply.dest_port == context.scan.port
            && reply.sequence == cookie
    }

    fn ipv4_at(data: &[u8], offset: usize) -> Ipv4Addr {
        Ipv4Addr::new(
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        )
    }
    struct ScanRuntime {
        source_ip: Ipv4Addr,
        seed: [u8; 32],
        perm: Permutation,
        cap: pcap::Capture<pcap::Active>,
        raw: Socket,
        stopping: Arc<AtomicBool>,
        start: Instant,
        bucket: TokenBucket,
    }

    fn scan_runtime(job: &PreparedJob, cfg: &Config) -> anyhow::Result<ScanRuntime> {
        let source_ip = resolve_source_ip(cfg)?;
        verify_rate_limit(cfg)?;
        let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
        let perm = Permutation::new(job.meta.target_count, seed)?;
        let cap = capture_socket(cfg)?;
        let raw = raw_socket(cfg)?;
        let rate =
            cfg.network.provider_egress_mbps * 1_000_000.0 / 8.0 * cfg.network.application_ratio;
        let stopping = Arc::new(AtomicBool::new(false));
        install_stop_handler(&stopping)?;
        Ok(ScanRuntime {
            source_ip,
            seed,
            perm,
            cap,
            raw,
            stopping,
            start: Instant::now(),
            bucket: TokenBucket::new(rate, 0.1),
        })
    }

    fn verify_rate_limit(cfg: &Config) -> anyhow::Result<()> {
        if cfg.network.require_tc {
            verify_tc(cfg)?;
        }
        Ok(())
    }

    fn capture_socket(cfg: &Config) -> anyhow::Result<pcap::Capture<pcap::Active>> {
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
        Ok(cap.setnonblock()?)
    }

    fn raw_socket(cfg: &Config) -> anyhow::Result<Socket> {
        let raw = Socket::new(Domain::IPV4, Type::RAW, Some(SockProtocol::TCP))?;
        raw.set_header_included_v4(true)?;
        raw.bind_device(Some(cfg.network.interface.as_bytes()))?;
        Ok(raw)
    }

    fn install_stop_handler(stopping: &Arc<AtomicBool>) -> anyhow::Result<()> {
        let signal = stopping.clone();
        ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))?;
        Ok(())
    }

    pub fn run(job: &mut PreparedJob, cfg: &Config) -> anyhow::Result<ScanSummary> {
        let mut runtime = scan_runtime(job, cfg)?;
        let target_file = File::open(job.dir.join("targets.bin"))?;
        let targets = unsafe { Mmap::map(&target_file)? };
        let mut states = job.states()?;
        send_rounds(job, cfg, &mut runtime, &targets, &mut states)?;
        let summary = finish_scan(job, cfg, &mut runtime, targets, states)?;
        Ok(summary)
    }

    fn send_rounds(
        job: &mut PreparedJob,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        targets: &[u8],
        states: &mut [u8],
    ) -> anyhow::Result<()> {
        'rounds: for round in job.meta.round..cfg.scan.syn_attempts {
            let start_order = if round == job.meta.round {
                job.meta.next_index
            } else {
                0
            };
            job.meta.round = round;
            for order in start_order..job.meta.target_count {
                if runtime.stopping.load(Ordering::SeqCst) {
                    job.checkpoint(order)?;
                    break 'rounds;
                }
                if send_target(order, cfg, runtime, targets, states)? {
                    job.meta.packets_sent = job.meta.packets_sent.saturating_add(1);
                }
                receive_replies(cfg, runtime, targets, states);
                // Persist periodically; an atomic fsync per target makes large
                // scans unusable. Ctrl+C always writes the exact next index.
                if (order + 1) % 10_000 == 0 {
                    job.checkpoint(order + 1)?;
                }
            }
            job.meta.round = round + 1;
            job.checkpoint(0)?;
            if round + 1 < cfg.scan.syn_attempts {
                pause_between_rounds(cfg, runtime, targets, states);
            }
        }
        Ok(())
    }

    fn send_target(
        order: u64,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        targets: &[u8],
        states: &[u8],
    ) -> anyhow::Result<bool> {
        let idx = runtime.perm.get(order) as usize;
        if states[idx] != 0 {
            return Ok(false);
        }
        let ip = target_ip(targets, idx);
        let wait = runtime.bucket.consume_at(
            packet::SYN_WIRE_BYTES,
            runtime.start.elapsed().as_secs_f64(),
        );
        if !wait.is_zero() {
            thread::sleep(wait);
        }
        let seq = packet::syn_cookie(
            &runtime.seed,
            runtime.source_ip,
            ip,
            cfg.scan.source_port,
            cfg.scan.port,
        );
        let packet = packet::SynPacket {
            src: runtime.source_ip,
            dst: ip,
            source_port: cfg.scan.source_port,
            dest_port: cfg.scan.port,
            seq,
            mss: 1460,
        }
        .encode();
        runtime
            .raw
            .send_to(&packet, &SocketAddrV4::new(ip, cfg.scan.port).into())?;
        Ok(true)
    }

    fn pause_between_rounds(
        cfg: &Config,
        runtime: &mut ScanRuntime,
        targets: &[u8],
        states: &mut [u8],
    ) {
        thread::sleep(Duration::from_secs(1));
        receive_replies(cfg, runtime, targets, states);
    }

    fn receive_replies(cfg: &Config, runtime: &mut ScanRuntime, targets: &[u8], states: &mut [u8]) {
        let mut context = ReplyContext {
            states,
            targets,
            secret: &runtime.seed,
            src: runtime.source_ip,
            scan: &cfg.scan,
        };
        receive(&mut runtime.cap, &mut context);
    }

    fn finish_scan(
        job: &mut PreparedJob,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        targets: Mmap,
        mut states: memmap2::MmapMut,
    ) -> anyhow::Result<ScanSummary> {
        thread::sleep(Duration::from_secs(1));
        receive_replies(cfg, runtime, &targets, &mut states);
        states.flush()?;
        record_capture_stats(job, &mut runtime.cap)?;
        let completed = job.meta.round >= cfg.scan.syn_attempts;
        let next_index =
            final_checkpoint_index(completed, job.meta.target_count, job.meta.next_index);
        job.checkpoint(next_index)?;
        let summary = summarize_states(completed, job, &states);
        let open_targets = open_targets(&targets, &states);
        drop(states);
        drop(targets);
        crate::job::save_summary(&job.dir, &summary)?;
        tokio::runtime::Runtime::new()?.block_on(banner_pipeline(
            &job.dir,
            open_targets,
            runtime.source_ip,
            cfg,
            &job.meta.scan_id,
        ))?;
        Ok(summary)
    }

    fn record_capture_stats(
        job: &mut PreparedJob,
        cap: &mut pcap::Capture<pcap::Active>,
    ) -> anyhow::Result<()> {
        let stats = cap.stats()?;
        let run_drops = u64::from(stats.dropped) + u64::from(stats.if_dropped);
        job.meta.pcap_drops = job.meta.pcap_drops.saturating_add(run_drops);
        job.meta.degraded |= run_drops > 0;
        Ok(())
    }

    fn summarize_states(completed: bool, job: &PreparedJob, states: &[u8]) -> ScanSummary {
        let mut summary = ScanSummary {
            completed,
            sent: job.meta.packets_sent,
            pcap_drops: job.meta.pcap_drops,
            ..Default::default()
        };
        for &v in states {
            match v {
                3 => summary.open += 1,
                2 => summary.closed += 1,
                1 => summary.unreachable += 1,
                _ => summary.no_response += 1,
            }
        }
        summary
    }

    fn open_targets(targets: &[u8], states: &[u8]) -> Vec<Ipv4Addr> {
        (0..states.len())
            .filter(|&i| states[i] == 3)
            .map(|i| target_ip(targets, i))
            .collect()
    }

    fn target_ip(targets: &[u8], index: usize) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            targets[index * 4..index * 4 + 4].try_into().unwrap(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::{Protocol, ScanConfig};

        fn scan_config() -> ScanConfig {
            ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                syn_attempts: 1,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 1,
                banner_concurrency: 1,
                banner_connects_per_second: 1,
            }
        }

        fn ipv4_packet(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
            let total = 20 + payload.len();
            let mut packet = vec![0; total];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            packet[20..].copy_from_slice(payload);
            packet
        }

        fn tcp_segment(source_port: u16, dest_port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
            let mut tcp = vec![0; 20];
            tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
            tcp[2..4].copy_from_slice(&dest_port.to_be_bytes());
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp[8..12].copy_from_slice(&ack.to_be_bytes());
            tcp[12] = 5 << 4;
            tcp[13] = flags;
            tcp
        }

        fn ethernet_ipv4(mut packet: Vec<u8>) -> Vec<u8> {
            let mut frame = vec![0; 14];
            frame[12..14].copy_from_slice(&[0x08, 0x00]);
            frame.append(&mut packet);
            frame
        }

        fn sll_ipv4(mut packet: Vec<u8>) -> Vec<u8> {
            let mut frame = vec![0; 16];
            frame[14..16].copy_from_slice(&[0x08, 0x00]);
            frame.append(&mut packet);
            frame
        }

        #[test]
        fn ipv4_header_accepts_raw_ipv4() {
            let packet = ipv4_packet(6, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, &[0; 20]);

            assert_eq!(ipv4_header(&packet), Some((0, 20, 6)));
        }

        #[test]
        fn ipv4_header_accepts_ethernet_ipv4() {
            let packet = ethernet_ipv4(ipv4_packet(
                6,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                &[0; 20],
            ));

            assert_eq!(ipv4_header(&packet), Some((14, 20, 6)));
        }

        #[test]
        fn ipv4_header_accepts_linux_cooked_capture_ipv4() {
            let packet = sll_ipv4(ipv4_packet(
                6,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::UNSPECIFIED,
                &[0; 20],
            ));

            assert_eq!(ipv4_header(&packet), Some((16, 20, 6)));
        }

        #[test]
        fn ipv4_header_rejects_linux_cooked_capture_non_ipv4() {
            let mut packet = vec![0; 16 + 20];
            packet[14..16].copy_from_slice(&[0x86, 0xdd]);
            packet[16] = 0x45;

            assert_eq!(ipv4_header(&packet), None);
        }

        #[test]
        fn ipv4_header_rejects_truncated_frames() {
            assert_eq!(ipv4_header(&[0x45; 19]), None);

            let mut ethernet = vec![0; 14 + 19];
            ethernet[12..14].copy_from_slice(&[0x08, 0x00]);
            ethernet[14] = 0x45;
            assert_eq!(ipv4_header(&ethernet), None);

            let mut sll = vec![0; 16 + 19];
            sll[14..16].copy_from_slice(&[0x08, 0x00]);
            sll[16] = 0x45;
            assert_eq!(ipv4_header(&sll), None);
        }

        #[test]
        fn ethernet_syn_ack_marks_target_open() {
            let src = Ipv4Addr::new(192, 0, 2, 10);
            let remote = Ipv4Addr::new(198, 51, 100, 20);
            let secret = [7; 32];
            let scan = scan_config();
            let cookie = packet::syn_cookie(&secret, src, remote, scan.source_port, scan.port);
            let tcp = tcp_segment(scan.port, scan.source_port, 0, cookie.wrapping_add(1), 0x12);
            let packet = ethernet_ipv4(ipv4_packet(6, remote, src, &tcp));
            let (offset, ihl, _) = ipv4_header(&packet).unwrap();
            let mut states = [0];
            let targets = remote.octets();
            let mut context = ReplyContext {
                states: &mut states,
                targets: &targets,
                secret: &secret,
                src,
                scan: &scan,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_eq!(states[0], 3);
        }

        #[test]
        fn linux_cooked_capture_syn_ack_marks_target_open() {
            let src = Ipv4Addr::new(192, 0, 2, 10);
            let remote = Ipv4Addr::new(198, 51, 100, 20);
            let secret = [7; 32];
            let scan = scan_config();
            let cookie = packet::syn_cookie(&secret, src, remote, scan.source_port, scan.port);
            let tcp = tcp_segment(scan.port, scan.source_port, 0, cookie.wrapping_add(1), 0x12);
            let packet = sll_ipv4(ipv4_packet(6, remote, src, &tcp));
            let (offset, ihl, _) = ipv4_header(&packet).unwrap();
            let mut states = [0];
            let targets = remote.octets();
            let mut context = ReplyContext {
                states: &mut states,
                targets: &targets,
                secret: &secret,
                src,
                scan: &scan,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_eq!(states[0], 3);
        }

        #[test]
        fn linux_cooked_capture_rst_marks_target_closed() {
            let src = Ipv4Addr::new(192, 0, 2, 10);
            let remote = Ipv4Addr::new(198, 51, 100, 20);
            let secret = [7; 32];
            let scan = scan_config();
            let cookie = packet::syn_cookie(&secret, src, remote, scan.source_port, scan.port);
            let tcp = tcp_segment(scan.port, scan.source_port, 0, cookie.wrapping_add(1), 0x04);
            let packet = sll_ipv4(ipv4_packet(6, remote, src, &tcp));
            let (offset, ihl, _) = ipv4_header(&packet).unwrap();
            let mut states = [0];
            let targets = remote.octets();
            let mut context = ReplyContext {
                states: &mut states,
                targets: &targets,
                secret: &secret,
                src,
                scan: &scan,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_eq!(states[0], 2);
        }

        #[test]
        fn linux_cooked_capture_icmp_unreachable_marks_target_unreachable() {
            let src = Ipv4Addr::new(192, 0, 2, 10);
            let remote = Ipv4Addr::new(198, 51, 100, 20);
            let router = Ipv4Addr::new(203, 0, 113, 1);
            let secret = [7; 32];
            let scan = scan_config();
            let cookie = packet::syn_cookie(&secret, src, remote, scan.source_port, scan.port);
            let inner_tcp = tcp_segment(scan.source_port, scan.port, cookie, 0, 0x02);
            let inner_ip = ipv4_packet(6, src, remote, &inner_tcp);
            let mut icmp = vec![3, 1, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&inner_ip[..28]);
            let packet = sll_ipv4(ipv4_packet(1, router, src, &icmp));
            let (offset, ihl, _) = ipv4_header(&packet).unwrap();
            let mut states = [0];
            let targets = remote.octets();
            let mut context = ReplyContext {
                states: &mut states,
                targets: &targets,
                secret: &secret,
                src,
                scan: &scan,
            };

            handle_icmp_reply(&packet, offset, ihl, &mut context);

            assert_eq!(states[0], 1);
        }
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
