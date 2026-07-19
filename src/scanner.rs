use crate::{Config, job::PreparedJob, packet::SYN_WIRE_BYTES, permutation::Permutation};
use base64::Engine;
use std::{
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::PathBuf,
};
#[cfg(target_os = "linux")]
use std::{path::Path, process::Command, sync::Arc, time::Duration};

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
    let syn_seconds = bytes as f64 / bps;
    let time_budget_secs = cfg.budget.time_budget_secs;
    let required_syn_application_mbps =
        time_budget_secs.map(|secs| bytes as f64 * 8.0 / secs as f64 / 1_000_000.0);
    let recommended_provider_egress_mbps =
        required_syn_application_mbps.map(|mbps| mbps / cfg.network.application_ratio);
    let banner_worst_case_secs = f64::from(cfg.scan.banner_attempts)
        * (cfg.scan.connect_timeout_ms + cfg.scan.banner_timeout_ms) as f64
        / 1000.0;
    let concurrency_limited_cps = if banner_worst_case_secs > 0.0 {
        cfg.scan.banner_concurrency as f64 / banner_worst_case_secs
    } else {
        f64::INFINITY
    };
    let banner_capacity_cps =
        f64::from(cfg.scan.banner_connects_per_second).min(concurrency_limited_cps);
    let expected_open = cfg
        .budget
        .expected_open_ratio
        .map(|ratio| count as f64 * ratio);
    let banner_budget_capacity_open =
        time_budget_secs.map(|secs| banner_capacity_cps * secs as f64);
    let banner_seconds = expected_open.map(|open| {
        if banner_capacity_cps > 0.0 {
            open / banner_capacity_cps
        } else {
            f64::INFINITY
        }
    });
    let estimated_total_seconds = banner_seconds.map(|banner| syn_seconds.max(banner));
    let mut budget_warnings = Vec::new();
    if let Some(secs) = time_budget_secs {
        let budget = secs as f64;
        if syn_seconds > budget {
            budget_warnings.push("SYN bandwidth is insufficient for the time budget".into());
        }
        match expected_open {
            Some(open) => {
                if let Some(capacity) = banner_budget_capacity_open {
                    if open > capacity {
                        if f64::from(cfg.scan.banner_connects_per_second) <= concurrency_limited_cps
                        {
                            budget_warnings
                                .push("banner_connects_per_second is insufficient".into());
                        } else {
                            budget_warnings
                                .push("banner timeout/concurrency limits banner throughput".into());
                        }
                    }
                }
            }
            None => budget_warnings
                .push("expected_open_ratio is not configured; banner workload is unknown".into()),
        }
    }
    Estimate {
        targets: count,
        worst_packets: packets,
        estimated_wire_bytes: bytes,
        minimum_seconds: syn_seconds,
        syn_seconds,
        required_syn_application_mbps,
        recommended_provider_egress_mbps,
        banner_capacity_cps,
        banner_budget_capacity_open,
        expected_open,
        banner_seconds,
        estimated_total_seconds,
        budget_warnings,
    }
}
#[derive(Debug, serde::Serialize)]
pub struct Estimate {
    pub targets: u64,
    pub worst_packets: u64,
    pub estimated_wire_bytes: u64,
    pub minimum_seconds: f64,
    pub syn_seconds: f64,
    pub required_syn_application_mbps: Option<f64>,
    pub recommended_provider_egress_mbps: Option<f64>,
    pub banner_capacity_cps: f64,
    pub banner_budget_capacity_open: Option<f64>,
    pub expected_open: Option<f64>,
    pub banner_seconds: Option<f64>,
    pub estimated_total_seconds: Option<f64>,
    pub budget_warnings: Vec<String>,
}

pub fn dry_run(job: &PreparedJob) -> anyhow::Result<String> {
    use memmap2::Mmap;
    use std::fs::File;
    let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
    let p = Permutation::new(job.meta.target_count, seed)?;
    let file = File::open(job.dir.join("targets.bin"))?;
    let port_file = File::open(job.dir.join("ports.bin"))?;
    let protocol_file = File::open(job.dir.join("protocols.bin"))?;
    let targets = unsafe { Mmap::map(&file)? };
    let ports = unsafe { Mmap::map(&port_file)? };
    let protocols = unsafe { Mmap::map(&protocol_file)? };
    let mut h = blake3::Hasher::new();
    for i in 0..job.meta.target_count {
        let index = p.get(i) as usize;
        h.update(&targets[index * 4..index * 4 + 4]);
        h.update(&ports[index * 2..index * 2 + 2]);
        h.update(&protocols[index..index + 1]);
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
    if cfg.simulation.enabled {
        return simulation::run(job, cfg);
    }
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

fn effective_runtime_limit_secs(cfg: &Config) -> Option<u64> {
    let budget = cfg
        .budget
        .enforce_time_budget
        .then_some(cfg.budget.time_budget_secs)
        .flatten();
    match (cfg.scan.max_runtime_secs, budget) {
        (Some(scan), Some(budget)) => Some(scan.min(budget)),
        (Some(scan), None) => Some(scan),
        (None, Some(budget)) => Some(budget),
        (None, None) => None,
    }
}

async fn banner_pipeline(
    job_dir: PathBuf,
    receiver: std::sync::mpsc::Receiver<Option<OpenTarget>>,
    source_ip: Ipv4Addr,
    cfg: &Config,
    scan_id: String,
    budget: AsyncTokenBucket,
    banner_state_file: Arc<std::sync::Mutex<std::fs::File>>,
) -> anyhow::Result<()> {
    use tokio::{sync::Semaphore, task::JoinSet, time};
    let sem = Arc::new(Semaphore::new(cfg.scan.banner_concurrency));
    let mut ticker = time::interval(Duration::from_secs_f64(
        1.0 / f64::from(cfg.scan.banner_connects_per_second),
    ));
    let mut tasks = JoinSet::new();
    loop {
        drain_completed_banner_tasks(&mut tasks, &job_dir, &banner_state_file).await?;
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(target)) => {
                ticker.tick().await;
                let permit = sem.clone().acquire_owned().await?;
                let scan = cfg.scan.clone();
                let scan_id = scan_id.clone();
                let budget = budget.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result = inspect_banner(
                        &scan_id,
                        target.ip,
                        source_ip,
                        &scan,
                        target.service,
                        target.observation,
                        &budget,
                    )
                    .await?;
                    Ok::<_, anyhow::Error>((target.index, result))
                });
            }
            Ok(None) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    while !tasks.is_empty() {
        drain_completed_banner_tasks(&mut tasks, &job_dir, &banner_state_file).await?;
        if !tasks.is_empty() {
            time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(())
}

async fn drain_completed_banner_tasks(
    tasks: &mut tokio::task::JoinSet<anyhow::Result<(usize, crate::ResultV1)>>,
    job_dir: &std::path::Path,
    banner_state_file: &Arc<std::sync::Mutex<std::fs::File>>,
) -> anyhow::Result<()> {
    while let Some(result) = tasks.try_join_next() {
        let (index, result) = result??;
        crate::job::append_event(job_dir, &result)?;
        use std::io::{Seek, SeekFrom, Write};
        let mut file = banner_state_file
            .lock()
            .expect("banner state file mutex poisoned");
        file.seek(SeekFrom::Start(index as u64))?;
        file.write_all(&[crate::job::BANNER_DONE])?;
        file.sync_data()?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct OpenTarget {
    index: usize,
    ip: Ipv4Addr,
    service: crate::config::ServiceConfig,
    observation: SynObservation,
}

#[derive(Clone, Copy)]
struct SynObservation {
    attempts: u8,
    rtt_ms: Option<f64>,
    conflicting_observations: u32,
}

#[derive(Clone)]
struct AsyncTokenBucket {
    inner: Arc<tokio::sync::Mutex<crate::rate::TokenBucket>>,
    start: std::time::Instant,
}

impl AsyncTokenBucket {
    fn new(bucket: crate::rate::TokenBucket, start: std::time::Instant) -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(bucket)),
            start,
        }
    }

    async fn consume(&self, bytes: u64) {
        let wait = self.reserve(bytes).await;
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }

    async fn reserve(&self, bytes: u64) -> Duration {
        let mut bucket = self.inner.lock().await;
        bucket.consume_at(bytes, self.start.elapsed().as_secs_f64())
    }
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
    service: crate::config::ServiceConfig,
    syn: SynObservation,
    budget: &AsyncTokenBucket,
) -> anyhow::Result<crate::ResultV1> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut observation = BannerObservation {
        raw: Vec::new(),
        status: crate::BannerStatus::ConnectFailed,
        parsed: None,
    };
    for _ in 0..scan.banner_attempts {
        budget.consume(SYN_WIRE_BYTES).await;
        let mut stream = match connect_banner(ip, source_ip, scan, service).await? {
            Ok(stream) => stream,
            Err(status) => {
                observation.status = status;
                continue;
            }
        };
        observation.raw.clear();
        observation.status = read_banner(&mut stream, scan, service, &mut observation.raw).await;
        if observation.status == crate::BannerStatus::Ok {
            match crate::protocol::parse(service.protocol, &observation.raw) {
                Ok(parsed) => observation.parsed = Some(parsed),
                Err(status) => observation.status = status,
            }
            break;
        }
        if terminal_banner_status(observation.status) {
            break;
        }
    }
    Ok(make_result(scan_id, ip, service, syn, observation))
}

async fn connect_banner(
    ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    scan: &crate::config::ScanConfig,
    service: crate::config::ServiceConfig,
) -> anyhow::Result<Result<tokio::net::TcpStream, crate::BannerStatus>> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddrV4::new(source_ip, 0).into())?;
    let connected = tokio::time::timeout(
        Duration::from_millis(scan.connect_timeout_ms),
        socket.connect(SocketAddrV4::new(ip, service.port).into()),
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
    service: crate::config::ServiceConfig,
    evidence: &mut Vec<u8>,
) -> crate::BannerStatus {
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(status) = banner_completion(scan, service, evidence) {
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
    service: crate::config::ServiceConfig,
    evidence: &mut Vec<u8>,
) -> Option<crate::BannerStatus> {
    match crate::protocol::message_len(service.protocol, evidence, scan.banner_max_bytes) {
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
    service: crate::config::ServiceConfig,
    syn: SynObservation,
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
        result_id: crate::result::result_id(scan_id, ip, service.port),
        scan_id: scan_id.into(),
        ip,
        port: service.port,
        protocol: service.protocol,
        state: crate::TargetState::Open,
        syn_attempts: syn.attempts,
        rtt_ms: syn.rtt_ms,
        conflicting_observations: syn.conflicting_observations,
        first_observed_at: Some(observed.clone()),
        last_observed_at: Some(observed),
        banner_status: Some(observation.status),
        banner_base64: (!observation.raw.is_empty())
            .then(|| base64::engine::general_purpose::STANDARD.encode(&observation.raw)),
        banner_text: parsed.text,
        ssh: parsed.ssh,
        ftp: parsed.ftp,
        mysql: parsed.mysql,
        smtp: parsed.smtp,
        redis: parsed.redis,
        postgres: parsed.postgres,
    }
}
#[derive(Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ScanSummary {
    pub completed: bool,
    pub sent: u64,
    #[serde(default)]
    pub syn_mss: Option<u16>,
    pub open: u64,
    pub closed: u64,
    pub unreachable: u64,
    pub no_response: u64,
    pub pcap_drops: u64,
    #[serde(default)]
    pub conflicting_observations: u64,
    #[serde(default)]
    pub interface_tx_packets: Option<u64>,
    #[serde(default)]
    pub interface_tx_bytes: Option<u64>,
    #[serde(default)]
    pub banner_queued: u64,
    #[serde(default)]
    pub banner_done: u64,
    #[serde(default)]
    pub banner_failed_or_incomplete: u64,
    #[serde(default)]
    pub timed_out: bool,
}

fn final_checkpoint_index(completed: bool, target_count: u64, next_index: u64) -> u64 {
    if completed { target_count } else { next_index }
}

fn read_u32(data: &[u8], index: usize) -> u32 {
    let offset = index * 4;
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn write_u32(data: &mut [u8], index: usize, value: u32) {
    let offset = index * 4;
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn decode_rtt_ms(rtts: &[u8], index: usize) -> Option<f64> {
    let stored = read_u32(rtts, index);
    (stored != 0).then(|| f64::from(stored - 1) / 1000.0)
}

fn target_ip(targets: &[u8], index: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be_bytes(
        targets[index * 4..index * 4 + 4].try_into().unwrap(),
    ))
}

fn target_port(ports: &[u8], index: usize) -> u16 {
    let offset = index * 2;
    u16::from_be_bytes(ports[offset..offset + 2].try_into().unwrap())
}

fn target_protocol(protocols: &[u8], index: usize) -> crate::Protocol {
    crate::job::protocol_from_code(protocols[index]).unwrap_or(crate::Protocol::Ssh)
}

fn target_service(ports: &[u8], protocols: &[u8], index: usize) -> crate::config::ServiceConfig {
    crate::config::ServiceConfig {
        port: target_port(ports, index),
        protocol: target_protocol(protocols, index),
    }
}

fn summary_banner_counts(summary: &mut ScanSummary, banner_states: &[u8]) {
    summary.banner_queued = 0;
    summary.banner_done = 0;
    for &state in banner_states {
        match state {
            crate::job::BANNER_QUEUED_OR_RUNNING => summary.banner_queued += 1,
            crate::job::BANNER_DONE => summary.banner_done += 1,
            _ => {}
        }
    }
    summary.banner_failed_or_incomplete = summary.open.saturating_sub(summary.banner_done);
}

fn summarize_state_bytes(
    completed: bool,
    job: &PreparedJob,
    states: &[u8],
    conflicts: &[u8],
    banner_states: &[u8],
    timed_out: bool,
) -> ScanSummary {
    let mut summary = ScanSummary {
        completed,
        sent: job.meta.packets_sent,
        pcap_drops: job.meta.pcap_drops,
        timed_out,
        ..Default::default()
    };
    for &v in states {
        match crate::result::decode_state_byte(v)
            .map(|(state, _)| state)
            .unwrap_or(crate::TargetState::NoResponse)
        {
            crate::TargetState::Open => summary.open += 1,
            crate::TargetState::Closed => summary.closed += 1,
            crate::TargetState::Unreachable => summary.unreachable += 1,
            crate::TargetState::NoResponse => summary.no_response += 1,
        }
    }
    for index in 0..states.len() {
        summary.conflicting_observations += u64::from(read_u32(conflicts, index));
    }
    summary_banner_counts(&mut summary, banner_states);
    summary
}

mod simulation {
    use super::*;
    use memmap2::Mmap;
    use std::fs::File;

    pub fn run(job: &mut PreparedJob, cfg: &Config) -> anyhow::Result<ScanSummary> {
        job.ensure_endpoint_files(cfg)?;
        let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
        let perm = Permutation::new(job.meta.target_count, seed)?;
        let target_file = File::open(job.dir.join("targets.bin"))?;
        let port_file = File::open(job.dir.join("ports.bin"))?;
        let protocol_file = File::open(job.dir.join("protocols.bin"))?;
        let targets = unsafe { Mmap::map(&target_file)? };
        let ports = unsafe { Mmap::map(&port_file)? };
        let protocols = unsafe { Mmap::map(&protocol_file)? };
        let mut states = job.states()?;
        let mut rtts = job.rtts()?;
        let mut sent_times = job.sent_times()?;
        let conflicts = job.conflicts()?;
        let mut banner_states = crate::job::ensure_banner_state_backfilled(job, cfg)?;

        send_rounds(
            job,
            cfg,
            &perm,
            &targets,
            &ports,
            &protocols,
            &mut states,
            &mut rtts,
            &mut sent_times,
            &mut banner_states,
        )?;

        states.flush()?;
        rtts.flush()?;
        sent_times.flush()?;
        conflicts.flush()?;
        banner_states.flush()?;
        let completed = job.meta.round >= cfg.scan.syn_attempts;
        let next_index =
            final_checkpoint_index(completed, job.meta.target_count, job.meta.next_index);
        job.checkpoint(next_index)?;
        let summary =
            summarize_state_bytes(completed, job, &states, &conflicts, &banner_states, false);
        crate::job::save_summary(&job.dir, &summary)?;
        Ok(summary)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_rounds(
        job: &mut PreparedJob,
        cfg: &Config,
        perm: &Permutation,
        targets: &[u8],
        ports: &[u8],
        protocols: &[u8],
        states: &mut [u8],
        rtts: &mut [u8],
        sent_times: &mut [u8],
        banner_states: &mut [u8],
    ) -> anyhow::Result<()> {
        for round in job.meta.round..cfg.scan.syn_attempts {
            let start_order = if round == job.meta.round {
                job.meta.next_index
            } else {
                0
            };
            job.meta.round = round;
            let attempts = round + 1;
            for order in start_order..job.meta.target_count {
                let index = perm.get(order) as usize;
                if state_rank(states[index]) != crate::TargetState::NoResponse.rank() {
                    continue;
                }
                job.meta.packets_sent = job.meta.packets_sent.saturating_add(1);
                write_u32(sent_times, index, simulated_sent_ms(order, attempts));
                let endpoint = SimEndpoint {
                    ip: target_ip(targets, index),
                    service: target_service(ports, protocols, index),
                };
                let state = simulated_state(cfg, &job.meta.scan_id, endpoint);
                if state == crate::TargetState::NoResponse {
                    continue;
                }
                states[index] = crate::result::encode_state_byte(state, attempts);
                write_u32(
                    rtts,
                    index,
                    simulated_rtt_us(cfg, &job.meta.scan_id, endpoint),
                );
                if state == crate::TargetState::Open && cfg.simulation.banner {
                    append_banner_event(job, endpoint, index, attempts, rtts, banner_states)?;
                }
                if order % 10_000 == 0 {
                    job.checkpoint(order + 1)?;
                }
            }
            job.meta.round = round + 1;
            job.checkpoint(0)?;
        }
        Ok(())
    }

    fn append_banner_event(
        job: &PreparedJob,
        endpoint: SimEndpoint,
        index: usize,
        attempts: u8,
        rtts: &[u8],
        banner_states: &mut [u8],
    ) -> anyhow::Result<()> {
        if banner_states[index] == crate::job::BANNER_DONE {
            return Ok(());
        }
        let raw = simulated_banner(endpoint.service.protocol);
        let parsed = crate::protocol::parse(endpoint.service.protocol, &raw).map_err(|status| {
            anyhow::anyhow!(
                "parse simulated {:?} banner failed with {:?}",
                endpoint.service.protocol,
                status
            )
        })?;
        let result = make_result(
            &job.meta.scan_id,
            endpoint.ip,
            endpoint.service,
            SynObservation {
                attempts,
                rtt_ms: decode_rtt_ms(rtts, index),
                conflicting_observations: 0,
            },
            BannerObservation {
                raw,
                status: crate::BannerStatus::Ok,
                parsed: Some(parsed),
            },
        );
        crate::job::append_event(&job.dir, &result)?;
        banner_states[index] = crate::job::BANNER_DONE;
        Ok(())
    }

    #[derive(Clone, Copy)]
    struct SimEndpoint {
        ip: Ipv4Addr,
        service: crate::config::ServiceConfig,
    }

    fn simulated_state(cfg: &Config, scan_id: &str, endpoint: SimEndpoint) -> crate::TargetState {
        let sample = hash_unit(cfg, scan_id, endpoint, b"state");
        let open = cfg.simulation.open_ratio;
        let closed = open + cfg.simulation.closed_ratio;
        let unreachable = closed + cfg.simulation.unreachable_ratio;
        if sample < open {
            crate::TargetState::Open
        } else if sample < closed {
            crate::TargetState::Closed
        } else if sample < unreachable {
            crate::TargetState::Unreachable
        } else {
            crate::TargetState::NoResponse
        }
    }

    fn simulated_rtt_us(cfg: &Config, scan_id: &str, endpoint: SimEndpoint) -> u32 {
        let sample = hash_unit(cfg, scan_id, endpoint, b"rtt");
        let rtt_ms = cfg.simulation.rtt_min_ms
            + (cfg.simulation.rtt_max_ms - cfg.simulation.rtt_min_ms) * sample;
        let micros = (rtt_ms * 1000.0).round();
        (micros as u32).saturating_add(1)
    }

    fn hash_unit(cfg: &Config, scan_id: &str, endpoint: SimEndpoint, domain: &[u8]) -> f64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(cfg.simulation.seed.as_bytes());
        hasher.update(scan_id.as_bytes());
        hasher.update(domain);
        hasher.update(&endpoint.ip.octets());
        hasher.update(&endpoint.service.port.to_be_bytes());
        hasher.update(&[crate::job::protocol_code(endpoint.service.protocol)]);
        let hash = hasher.finalize();
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&hash.as_bytes()[..8]);
        u64::from_be_bytes(bytes) as f64 / (u64::MAX as f64 + 1.0)
    }

    fn simulated_sent_ms(order: u64, attempts: u8) -> u32 {
        let value = order
            .saturating_add(u64::from(attempts))
            .min(u64::from(u32::MAX));
        value as u32
    }

    fn state_rank(value: u8) -> u8 {
        crate::result::decode_state_byte(value)
            .map(|(state, _)| state.rank())
            .unwrap_or(crate::TargetState::NoResponse.rank())
    }

    fn simulated_banner(protocol: crate::Protocol) -> Vec<u8> {
        match protocol {
            crate::Protocol::Ssh => b"SSH-2.0-RiftMapSim_1.0\r\n".to_vec(),
            crate::Protocol::Ftp => b"220 riftmap-sim FTP ready\r\n".to_vec(),
            crate::Protocol::Mysql => mysql_banner(),
            crate::Protocol::Smtp => b"220 riftmap-sim ESMTP ready\r\n".to_vec(),
            crate::Protocol::Redis => b"+PONG\r\n".to_vec(),
            crate::Protocol::Postgres => postgres_banner(),
        }
    }

    fn mysql_banner() -> Vec<u8> {
        let mut payload = vec![10];
        payload.extend_from_slice(b"8.0.36-riftmap-sim\0");
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&0x1234u16.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&0x5678u16.to_le_bytes());
        let len = payload.len();
        let mut packet = vec![(len & 0xff) as u8, ((len >> 8) & 0xff) as u8, 0, 0];
        packet.extend_from_slice(&payload);
        packet
    }

    fn postgres_banner() -> Vec<u8> {
        let payload = b"SERROR\0Msimulated startup response\0\0";
        let len = (payload.len() + 4) as u32;
        let mut packet = vec![b'E'];
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::{packet, rate::TokenBucket};
    use anyhow::Context;
    use memmap2::Mmap;
    use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
    use std::{
        fs::File,
        mem,
        os::fd::AsRawFd,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc::{self, SyncSender},
        },
        thread,
        time::Instant,
    };
    fn find_index(targets: &[u8], ports: &[u8], ip: Ipv4Addr, port: u16) -> Option<usize> {
        let needle = u32::from(ip);
        let n = targets.len() / 4;
        let mut lo = 0;
        let mut hi = n;
        while lo < hi {
            let m = (lo + hi) / 2;
            let v = u32::from_be_bytes(targets[m * 4..m * 4 + 4].try_into().unwrap());
            if v < needle { lo = m + 1 } else { hi = m }
        }
        while lo < n && targets[lo * 4..lo * 4 + 4] == needle.to_be_bytes() {
            let offset = lo * 2;
            if u16::from_be_bytes(ports[offset..offset + 2].try_into().unwrap()) == port {
                return Some(lo);
            }
            lo += 1;
        }
        None
    }
    struct ReplyContext<'a> {
        states: &'a mut [u8],
        rtts: &'a mut [u8],
        conflicts: &'a mut [u8],
        sent_times: &'a [u8],
        targets: &'a [u8],
        ports: &'a [u8],
        protocols: &'a [u8],
        banner_states: Option<&'a mut [u8]>,
        banner_sender: Option<&'a SyncSender<Option<OpenTarget>>>,
        secret: &'a [u8; 32],
        src: Ipv4Addr,
        source_port: u16,
        syn_attempts: u8,
        now_ms: u32,
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
            context.source_port,
            source_port,
        );
        if dest_port != context.source_port || !packet::valid_ack(cookie, ack) {
            return;
        }
        let Some(index) = find_index(context.targets, context.ports, remote, source_port) else {
            return;
        };
        let flags = data[tcp + 13];
        if flags & 0x12 == 0x12 {
            if observe_response(context, index, crate::TargetState::Open) {
                enqueue_banner(context, index);
            }
        } else if flags & 0x04 != 0 {
            observe_response(context, index, crate::TargetState::Closed);
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
        if let Some(index) = find_index(
            context.targets,
            context.ports,
            reply.remote,
            reply.dest_port,
        ) {
            observe_response(context, index, crate::TargetState::Unreachable);
        }
    }

    fn observe_response(
        context: &mut ReplyContext<'_>,
        index: usize,
        state: crate::TargetState,
    ) -> bool {
        let current = decoded_state(context.states[index]);
        if current != crate::TargetState::NoResponse && current != state {
            increment_u32(context.conflicts, index);
        }
        let mut upgraded = false;
        if state.rank() > current.rank() {
            context.states[index] = crate::result::encode_state_byte(state, context.syn_attempts);
            upgraded = true;
        }
        if read_u32(context.rtts, index) == 0 {
            if let Some(rtt_us) = response_rtt_us(context.sent_times, index, context.now_ms) {
                write_u32(context.rtts, index, rtt_us.saturating_add(1));
            }
        }
        upgraded && state == crate::TargetState::Open && current != crate::TargetState::Open
    }

    fn enqueue_banner(context: &mut ReplyContext<'_>, index: usize) {
        let Some(sender) = context.banner_sender else {
            return;
        };
        let Some(banner_states) = context.banner_states.as_deref_mut() else {
            return;
        };
        if banner_states[index] == crate::job::BANNER_DONE
            || banner_states[index] == crate::job::BANNER_QUEUED_OR_RUNNING
        {
            return;
        }
        banner_states[index] = crate::job::BANNER_QUEUED_OR_RUNNING;
        let target = OpenTarget {
            index,
            ip: target_ip(context.targets, index),
            service: target_service(context.ports, context.protocols, index),
            observation: SynObservation {
                attempts: context.syn_attempts,
                rtt_ms: decode_rtt_ms(context.rtts, index),
                conflicting_observations: read_u32(context.conflicts, index),
            },
        };
        let _ = sender.send(Some(target));
    }

    fn response_rtt_us(sent_times: &[u8], index: usize, now_ms: u32) -> Option<u32> {
        let sent_ms = read_u32(sent_times, index);
        (sent_ms != 0).then(|| now_ms.wrapping_sub(sent_ms).saturating_mul(1000))
    }

    fn state_rank(value: u8) -> u8 {
        decoded_state(value).rank()
    }

    fn decoded_state(value: u8) -> crate::TargetState {
        crate::result::decode_state_byte(value)
            .map(|(state, _)| state)
            .unwrap_or(crate::TargetState::NoResponse)
    }

    fn read_u32(data: &[u8], index: usize) -> u32 {
        let offset = index * 4;
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    }

    fn write_u32(data: &mut [u8], index: usize, value: u32) {
        let offset = index * 4;
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn increment_u32(data: &mut [u8], index: usize) {
        write_u32(data, index, read_u32(data, index).saturating_add(1));
    }

    fn elapsed_ms(start: Instant) -> u32 {
        let millis = start.elapsed().as_millis();
        millis.min(u128::from(u32::MAX)) as u32
    }

    fn decode_rtt_ms(rtts: &[u8], index: usize) -> Option<f64> {
        let stored = read_u32(rtts, index);
        (stored != 0).then(|| f64::from(stored - 1) / 1000.0)
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
            && reply.source_port == context.source_port
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
        tx_start: TxStats,
        mss: u16,
        timed_out: Arc<AtomicBool>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TxStats {
        packets: u64,
        bytes: u64,
    }

    impl TxStats {
        fn delta(self, end: Self) -> Self {
            Self {
                packets: end.packets.saturating_sub(self.packets),
                bytes: end.bytes.saturating_sub(self.bytes),
            }
        }
    }

    struct ScanBuffers<'a> {
        targets: &'a [u8],
        ports: &'a [u8],
        protocols: &'a [u8],
        states: &'a mut [u8],
        rtts: &'a mut [u8],
        sent_times: &'a mut [u8],
        conflicts: &'a mut [u8],
        banner_states: &'a mut [u8],
        banner_sender: &'a SyncSender<Option<OpenTarget>>,
    }

    struct ScanMaps {
        targets: Mmap,
        ports: Mmap,
        protocols: Mmap,
        states: memmap2::MmapMut,
        rtts: memmap2::MmapMut,
        sent_times: memmap2::MmapMut,
        conflicts: memmap2::MmapMut,
        banner_states: memmap2::MmapMut,
    }

    struct PreparedSyn {
        ip: Ipv4Addr,
        port: u16,
        packet: Vec<u8>,
    }

    struct BannerRunner {
        sender: SyncSender<Option<OpenTarget>>,
        handle: thread::JoinHandle<anyhow::Result<()>>,
    }

    const SENDMMSG_BATCH: usize = 64;

    fn scan_runtime(job: &PreparedJob, cfg: &Config) -> anyhow::Result<ScanRuntime> {
        let source_ip = resolve_source_ip(cfg)?;
        verify_rate_limit(cfg)?;
        let seed = crate::job::decode_seed(&job.meta.seed_hex)?;
        let perm = Permutation::new(job.meta.target_count, seed)?;
        let cap = capture_socket(cfg)?;
        let raw = raw_socket(cfg)?;
        let tx_start = interface_tx_stats(Path::new("/sys/class/net"), &cfg.network.interface)
            .context("read starting interface TX counters")?;
        let mss = interface_mss(Path::new("/sys/class/net"), &cfg.network.interface)
            .context("derive SYN MSS from interface MTU")?;
        let rate =
            cfg.network.provider_egress_mbps * 1_000_000.0 / 8.0 * cfg.network.application_ratio;
        let stopping = Arc::new(AtomicBool::new(false));
        install_stop_handler(&stopping)?;
        let timed_out = Arc::new(AtomicBool::new(false));
        if let Some(max_runtime_secs) = effective_runtime_limit_secs(cfg) {
            let stopping = stopping.clone();
            let timed_out = timed_out.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(max_runtime_secs));
                timed_out.store(true, Ordering::SeqCst);
                stopping.store(true, Ordering::SeqCst);
            });
        }
        Ok(ScanRuntime {
            source_ip,
            seed,
            perm,
            cap,
            raw,
            stopping,
            start: Instant::now(),
            bucket: TokenBucket::new(rate, 0.1),
            tx_start,
            mss,
            timed_out,
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

    fn interface_tx_stats(root: &Path, interface: &str) -> anyhow::Result<TxStats> {
        let stats = root.join(interface).join("statistics");
        Ok(TxStats {
            packets: read_counter(&stats.join("tx_packets"))?,
            bytes: read_counter(&stats.join("tx_bytes"))?,
        })
    }

    fn read_counter(path: &Path) -> anyhow::Result<u64> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(raw.trim().parse()?)
    }

    fn interface_mss(root: &Path, interface: &str) -> anyhow::Result<u16> {
        let raw = std::fs::read_to_string(root.join(interface).join("mtu"))?;
        mss_from_mtu(raw.trim().parse()?)
    }

    fn mss_from_mtu(mtu: u32) -> anyhow::Result<u16> {
        let mss = mtu
            .checked_sub(40)
            .ok_or_else(|| anyhow::anyhow!("interface MTU {mtu} is too small for IPv4/TCP"))?;
        anyhow::ensure!(mss > 0, "interface MTU {mtu} leaves zero TCP payload MSS");
        Ok(mss.min(u32::from(u16::MAX)) as u16)
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

    fn start_banner_runner(
        job: &PreparedJob,
        cfg: &Config,
        runtime: &ScanRuntime,
    ) -> anyhow::Result<BannerRunner> {
        let (sender, receiver) = mpsc::sync_channel(cfg.scan.banner_queue_capacity);
        let banner_state_file = Arc::new(std::sync::Mutex::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(job.dir.join("banner_state.bin"))?,
        ));
        let job_dir: PathBuf = job.dir.clone();
        let source_ip = runtime.source_ip;
        let cfg = cfg.clone();
        let scan_id = job.meta.scan_id.clone();
        let budget = AsyncTokenBucket::new(runtime.bucket.clone(), runtime.start);
        let worker_state_file = banner_state_file.clone();
        let handle = thread::spawn(move || {
            tokio::runtime::Runtime::new()?.block_on(banner_pipeline(
                job_dir,
                receiver,
                source_ip,
                &cfg,
                scan_id,
                budget,
                worker_state_file,
            ))
        });
        Ok(BannerRunner { sender, handle })
    }

    fn enqueue_resume_banner_targets(buffers: &mut ScanBuffers<'_>) -> anyhow::Result<()> {
        for index in 0..buffers.states.len() {
            let (state, attempts) = match crate::result::decode_state_byte(buffers.states[index]) {
                Ok(decoded) => decoded,
                Err(_) => continue,
            };
            if state != crate::TargetState::Open
                || buffers.banner_states[index] == crate::job::BANNER_DONE
            {
                continue;
            }
            buffers.banner_states[index] = crate::job::BANNER_QUEUED_OR_RUNNING;
            buffers.banner_sender.send(Some(OpenTarget {
                index,
                ip: target_ip(buffers.targets, index),
                service: target_service(buffers.ports, buffers.protocols, index),
                observation: SynObservation {
                    attempts,
                    rtt_ms: decode_rtt_ms(buffers.rtts, index),
                    conflicting_observations: read_u32(buffers.conflicts, index),
                },
            }))?;
        }
        Ok(())
    }

    pub fn run(job: &mut PreparedJob, cfg: &Config) -> anyhow::Result<ScanSummary> {
        job.ensure_endpoint_files(cfg)?;
        let mut runtime = scan_runtime(job, cfg)?;
        let target_file = File::open(job.dir.join("targets.bin"))?;
        let port_file = File::open(job.dir.join("ports.bin"))?;
        let protocol_file = File::open(job.dir.join("protocols.bin"))?;
        let targets = unsafe { Mmap::map(&target_file)? };
        let ports = unsafe { Mmap::map(&port_file)? };
        let protocols = unsafe { Mmap::map(&protocol_file)? };
        let mut states = job.states()?;
        let mut rtts = job.rtts()?;
        let mut sent_times = job.sent_times()?;
        let mut conflicts = job.conflicts()?;
        let mut banner_states = crate::job::ensure_banner_state_backfilled(job, cfg)?;
        let banner_runner = start_banner_runner(job, cfg, &runtime)?;
        {
            let mut buffers = ScanBuffers {
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                states: &mut states,
                rtts: &mut rtts,
                sent_times: &mut sent_times,
                conflicts: &mut conflicts,
                banner_states: &mut banner_states,
                banner_sender: &banner_runner.sender,
            };
            enqueue_resume_banner_targets(&mut buffers)?;
            send_rounds(job, cfg, &mut runtime, &mut buffers)?;
        }
        let summary = finish_scan(
            job,
            cfg,
            &mut runtime,
            banner_runner,
            ScanMaps {
                targets,
                ports,
                protocols,
                states,
                rtts,
                sent_times,
                conflicts,
                banner_states,
            },
        )?;
        Ok(summary)
    }

    fn send_rounds(
        job: &mut PreparedJob,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        buffers: &mut ScanBuffers<'_>,
    ) -> anyhow::Result<()> {
        'rounds: for round in job.meta.round..cfg.scan.syn_attempts {
            let start_order = if round == job.meta.round {
                job.meta.next_index
            } else {
                0
            };
            job.meta.round = round;
            let mut order = start_order;
            while order < job.meta.target_count {
                if runtime.stopping.load(Ordering::SeqCst) {
                    job.checkpoint(order)?;
                    break 'rounds;
                }
                let batch = prepare_syn_batch(&mut order, cfg, runtime, buffers);
                if !batch.is_empty() {
                    let sent = send_syn_batch(&runtime.raw, &batch)?;
                    job.meta.packets_sent = job.meta.packets_sent.saturating_add(sent as u64);
                }
                receive_replies(cfg, runtime, buffers, round + 1);
                // Persist periodically; an atomic fsync per target makes large
                // scans unusable. Ctrl+C always writes the exact next index.
                if order % 10_000 == 0 {
                    job.checkpoint(order)?;
                }
            }
            job.meta.round = round + 1;
            job.checkpoint(0)?;
            if round + 1 < cfg.scan.syn_attempts {
                pause_between_rounds(cfg, runtime, buffers, round + 1);
            }
        }
        Ok(())
    }

    fn prepare_syn_batch(
        order: &mut u64,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        buffers: &mut ScanBuffers<'_>,
    ) -> Vec<PreparedSyn> {
        let mut batch = Vec::with_capacity(SENDMMSG_BATCH);
        while *order < buffers.states.len() as u64 && batch.len() < SENDMMSG_BATCH {
            let idx = runtime.perm.get(*order) as usize;
            *order += 1;
            if state_rank(buffers.states[idx]) != crate::TargetState::NoResponse.rank() {
                continue;
            }
            let ip = target_ip(buffers.targets, idx);
            let service = target_service(buffers.ports, buffers.protocols, idx);
            let wait = runtime.bucket.consume_at(
                packet::SYN_WIRE_BYTES,
                runtime.start.elapsed().as_secs_f64(),
            );
            if !wait.is_zero() {
                thread::sleep(wait);
            }
            write_u32(buffers.sent_times, idx, elapsed_ms(runtime.start));
            let seq = packet::syn_cookie(
                &runtime.seed,
                runtime.source_ip,
                ip,
                cfg.scan.source_port,
                service.port,
            );
            batch.push(PreparedSyn {
                ip,
                port: service.port,
                packet: packet::SynPacket {
                    src: runtime.source_ip,
                    dst: ip,
                    source_port: cfg.scan.source_port,
                    dest_port: service.port,
                    seq,
                    mss: runtime.mss,
                }
                .encode(),
            });
        }
        batch
    }

    fn send_syn_batch(raw: &Socket, batch: &[PreparedSyn]) -> anyhow::Result<usize> {
        let mut sent = 0;
        while sent < batch.len() {
            sent += sendmmsg_once(raw, &batch[sent..])?;
        }
        Ok(sent)
    }

    fn sendmmsg_once(raw: &Socket, batch: &[PreparedSyn]) -> anyhow::Result<usize> {
        let mut addrs = batch
            .iter()
            .map(|syn| sockaddr_in(syn.ip, syn.port))
            .collect::<Vec<_>>();
        let mut iovecs = batch
            .iter()
            .map(|syn| libc::iovec {
                iov_base: syn.packet.as_ptr() as *mut libc::c_void,
                iov_len: syn.packet.len(),
            })
            .collect::<Vec<_>>();
        let mut messages = addrs
            .iter_mut()
            .zip(iovecs.iter_mut())
            .map(|(addr, iov)| {
                let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
                hdr.msg_name = addr as *mut libc::sockaddr_in as *mut libc::c_void;
                hdr.msg_namelen = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                hdr.msg_iov = iov;
                hdr.msg_iovlen = 1;
                libc::mmsghdr {
                    msg_hdr: hdr,
                    msg_len: 0,
                }
            })
            .collect::<Vec<_>>();
        loop {
            let sent = unsafe {
                libc::sendmmsg(
                    raw.as_raw_fd(),
                    messages.as_mut_ptr(),
                    messages.len() as libc::c_uint,
                    0,
                )
            };
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }

    fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    fn pause_between_rounds(
        cfg: &Config,
        runtime: &mut ScanRuntime,
        buffers: &mut ScanBuffers<'_>,
        syn_attempts: u8,
    ) {
        thread::sleep(Duration::from_secs(1));
        receive_replies(cfg, runtime, buffers, syn_attempts);
    }

    fn receive_replies(
        cfg: &Config,
        runtime: &mut ScanRuntime,
        buffers: &mut ScanBuffers<'_>,
        syn_attempts: u8,
    ) {
        let mut context = ReplyContext {
            states: buffers.states,
            rtts: buffers.rtts,
            conflicts: buffers.conflicts,
            sent_times: buffers.sent_times,
            targets: buffers.targets,
            ports: buffers.ports,
            protocols: buffers.protocols,
            banner_states: Some(buffers.banner_states),
            banner_sender: Some(buffers.banner_sender),
            secret: &runtime.seed,
            src: runtime.source_ip,
            source_port: cfg.scan.source_port,
            syn_attempts,
            now_ms: elapsed_ms(runtime.start),
        };
        receive(&mut runtime.cap, &mut context);
    }

    fn finish_scan(
        job: &mut PreparedJob,
        cfg: &Config,
        runtime: &mut ScanRuntime,
        banner_runner: BannerRunner,
        mut maps: ScanMaps,
    ) -> anyhow::Result<ScanSummary> {
        thread::sleep(Duration::from_secs(1));
        {
            let mut buffers = ScanBuffers {
                targets: &maps.targets,
                ports: &maps.ports,
                protocols: &maps.protocols,
                states: &mut maps.states,
                rtts: &mut maps.rtts,
                sent_times: &mut maps.sent_times,
                conflicts: &mut maps.conflicts,
                banner_states: &mut maps.banner_states,
                banner_sender: &banner_runner.sender,
            };
            receive_replies(cfg, runtime, &mut buffers, current_attempt(job, cfg));
        }
        maps.states.flush()?;
        maps.rtts.flush()?;
        maps.conflicts.flush()?;
        record_capture_stats(job, &mut runtime.cap)?;
        let completed = job.meta.round >= cfg.scan.syn_attempts;
        let next_index =
            final_checkpoint_index(completed, job.meta.target_count, job.meta.next_index);
        job.checkpoint(next_index)?;
        let mut summary = summarize_states(
            completed,
            job,
            &maps.states,
            &maps.conflicts,
            &maps.banner_states,
            runtime.timed_out.load(Ordering::SeqCst),
        );
        summary.syn_mss = Some(runtime.mss);
        let _ = banner_runner.sender.send(None);
        banner_runner
            .handle
            .join()
            .map_err(|_| anyhow::anyhow!("banner worker thread panicked"))??;
        drop(maps);
        let banner_states = crate::job::ensure_banner_state_backfilled(job, cfg)?;
        summary_banner_counts(&mut summary, &banner_states);
        let tx_end = interface_tx_stats(Path::new("/sys/class/net"), &cfg.network.interface)
            .context("read ending interface TX counters")?;
        let tx_delta = runtime.tx_start.delta(tx_end);
        summary.interface_tx_packets = Some(tx_delta.packets);
        summary.interface_tx_bytes = Some(tx_delta.bytes);
        crate::job::save_summary(&job.dir, &summary)?;
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

    fn current_attempt(job: &PreparedJob, cfg: &Config) -> u8 {
        if job.meta.round >= cfg.scan.syn_attempts {
            cfg.scan.syn_attempts
        } else {
            job.meta.round + 1
        }
    }

    fn summarize_states(
        completed: bool,
        job: &PreparedJob,
        states: &[u8],
        conflicts: &[u8],
        banner_states: &[u8],
        timed_out: bool,
    ) -> ScanSummary {
        let mut summary = ScanSummary {
            completed,
            sent: job.meta.packets_sent,
            pcap_drops: job.meta.pcap_drops,
            timed_out,
            ..Default::default()
        };
        for &v in states {
            match crate::result::decode_state_byte(v)
                .map(|(state, _)| state)
                .unwrap_or(crate::TargetState::NoResponse)
            {
                crate::TargetState::Open => summary.open += 1,
                crate::TargetState::Closed => summary.closed += 1,
                crate::TargetState::Unreachable => summary.unreachable += 1,
                crate::TargetState::NoResponse => summary.no_response += 1,
            }
        }
        for index in 0..states.len() {
            summary.conflicting_observations += u64::from(read_u32(conflicts, index));
        }
        summary_banner_counts(&mut summary, banner_states);
        summary
    }

    fn summary_banner_counts(summary: &mut ScanSummary, banner_states: &[u8]) {
        summary.banner_queued = 0;
        summary.banner_done = 0;
        for &state in banner_states {
            match state {
                crate::job::BANNER_QUEUED_OR_RUNNING => summary.banner_queued += 1,
                crate::job::BANNER_DONE => summary.banner_done += 1,
                _ => {}
            }
        }
        summary.banner_failed_or_incomplete = summary.open.saturating_sub(summary.banner_done);
    }

    fn target_ip(targets: &[u8], index: usize) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            targets[index * 4..index * 4 + 4].try_into().unwrap(),
        ))
    }

    fn target_port(ports: &[u8], index: usize) -> u16 {
        let offset = index * 2;
        u16::from_be_bytes(ports[offset..offset + 2].try_into().unwrap())
    }

    fn target_protocol(protocols: &[u8], index: usize) -> crate::Protocol {
        crate::job::protocol_from_code(protocols[index]).unwrap_or(crate::Protocol::Ssh)
    }

    fn target_service(
        ports: &[u8],
        protocols: &[u8],
        index: usize,
    ) -> crate::config::ServiceConfig {
        crate::config::ServiceConfig {
            port: target_port(ports, index),
            protocol: target_protocol(protocols, index),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::config::{Protocol, ScanConfig};

        fn scan_config() -> ScanConfig {
            ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![],
                syn_attempts: 1,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 1,
                banner_concurrency: 1,
                banner_connects_per_second: 1,
                banner_queue_capacity: 8,
                max_runtime_secs: None,
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

        fn assert_state(value: u8, expected: crate::TargetState, attempts: u8) {
            assert_eq!(
                crate::result::decode_state_byte(value).unwrap(),
                (expected, attempts)
            );
        }

        #[test]
        fn tx_stats_delta_saturates_on_counter_reset() {
            let start = TxStats {
                packets: 100,
                bytes: 1000,
            };

            assert_eq!(
                start.delta(TxStats {
                    packets: 125,
                    bytes: 1500,
                }),
                TxStats {
                    packets: 25,
                    bytes: 500,
                }
            );
            assert_eq!(
                start.delta(TxStats {
                    packets: 90,
                    bytes: 900,
                }),
                TxStats {
                    packets: 0,
                    bytes: 0,
                }
            );
        }

        #[test]
        fn reads_interface_tx_stats_from_sysfs_shape() -> anyhow::Result<()> {
            let temp = tempfile::tempdir()?;
            let stats = temp.path().join("eth-test").join("statistics");
            std::fs::create_dir_all(&stats)?;
            std::fs::write(stats.join("tx_packets"), "42\n")?;
            std::fs::write(stats.join("tx_bytes"), "9001\n")?;

            assert_eq!(
                interface_tx_stats(temp.path(), "eth-test")?,
                TxStats {
                    packets: 42,
                    bytes: 9001,
                }
            );
            Ok(())
        }

        #[test]
        fn derives_mss_from_interface_mtu() -> anyhow::Result<()> {
            assert_eq!(mss_from_mtu(1500)?, 1460);
            assert_eq!(mss_from_mtu(1280)?, 1240);
            assert_eq!(mss_from_mtu(9000)?, 8960);
            assert!(mss_from_mtu(40).is_err());
            Ok(())
        }

        #[test]
        fn reads_interface_mss_from_sysfs_shape() -> anyhow::Result<()> {
            let temp = tempfile::tempdir()?;
            let interface = temp.path().join("eth-test");
            std::fs::create_dir_all(&interface)?;
            std::fs::write(interface.join("mtu"), "1500\n")?;

            assert_eq!(interface_mss(temp.path(), "eth-test")?, 1460);
            Ok(())
        }

        #[test]
        fn sockaddr_in_preserves_network_order_fields() {
            let addr = sockaddr_in(Ipv4Addr::new(198, 51, 100, 20), 22);

            assert_eq!(addr.sin_family, libc::AF_INET as libc::sa_family_t);
            assert_eq!(addr.sin_port, 22u16.to_be());
            assert_eq!(addr.sin_addr.s_addr.to_ne_bytes(), [198, 51, 100, 20]);
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
            let mut rtts = [0; 4];
            let mut conflicts = [0; 4];
            let mut sent_times = [0; 4];
            write_u32(&mut sent_times, 0, 90);
            let targets = remote.octets();
            let ports = scan.port.to_be_bytes();
            let protocols = [crate::job::protocol_code(scan.protocol)];
            let mut context = ReplyContext {
                states: &mut states,
                rtts: &mut rtts,
                conflicts: &mut conflicts,
                sent_times: &sent_times,
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                banner_states: None,
                banner_sender: None,
                secret: &secret,
                src,
                source_port: scan.source_port,
                syn_attempts: 1,
                now_ms: 100,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_state(states[0], crate::TargetState::Open, 1);
            assert_eq!(decode_rtt_ms(&rtts, 0), Some(10.0));
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
            let mut rtts = [0; 4];
            let mut conflicts = [0; 4];
            let mut sent_times = [0; 4];
            write_u32(&mut sent_times, 0, 80);
            let targets = remote.octets();
            let ports = scan.port.to_be_bytes();
            let protocols = [crate::job::protocol_code(scan.protocol)];
            let mut context = ReplyContext {
                states: &mut states,
                rtts: &mut rtts,
                conflicts: &mut conflicts,
                sent_times: &sent_times,
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                banner_states: None,
                banner_sender: None,
                secret: &secret,
                src,
                source_port: scan.source_port,
                syn_attempts: 1,
                now_ms: 100,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_state(states[0], crate::TargetState::Open, 1);
            assert_eq!(decode_rtt_ms(&rtts, 0), Some(20.0));
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
            let mut rtts = [0; 4];
            let mut conflicts = [0; 4];
            let mut sent_times = [0; 4];
            write_u32(&mut sent_times, 0, 75);
            let targets = remote.octets();
            let ports = scan.port.to_be_bytes();
            let protocols = [crate::job::protocol_code(scan.protocol)];
            let mut context = ReplyContext {
                states: &mut states,
                rtts: &mut rtts,
                conflicts: &mut conflicts,
                sent_times: &sent_times,
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                banner_states: None,
                banner_sender: None,
                secret: &secret,
                src,
                source_port: scan.source_port,
                syn_attempts: 1,
                now_ms: 100,
            };

            handle_tcp_reply(&packet, offset, ihl, &mut context);

            assert_state(states[0], crate::TargetState::Closed, 1);
            assert_eq!(decode_rtt_ms(&rtts, 0), Some(25.0));
        }

        #[test]
        fn conflicting_tcp_observation_is_counted_without_downgrade() {
            let src = Ipv4Addr::new(192, 0, 2, 10);
            let remote = Ipv4Addr::new(198, 51, 100, 20);
            let secret = [7; 32];
            let scan = scan_config();
            let cookie = packet::syn_cookie(&secret, src, remote, scan.source_port, scan.port);
            let syn_ack = sll_ipv4(ipv4_packet(
                6,
                remote,
                src,
                &tcp_segment(scan.port, scan.source_port, 0, cookie.wrapping_add(1), 0x12),
            ));
            let rst = sll_ipv4(ipv4_packet(
                6,
                remote,
                src,
                &tcp_segment(scan.port, scan.source_port, 0, cookie.wrapping_add(1), 0x04),
            ));
            let (syn_offset, syn_ihl, _) = ipv4_header(&syn_ack).unwrap();
            let (rst_offset, rst_ihl, _) = ipv4_header(&rst).unwrap();
            let mut states = [0];
            let mut rtts = [0; 4];
            let mut conflicts = [0; 4];
            let mut sent_times = [0; 4];
            write_u32(&mut sent_times, 0, 90);
            let targets = remote.octets();
            let ports = scan.port.to_be_bytes();
            let protocols = [crate::job::protocol_code(scan.protocol)];
            let mut context = ReplyContext {
                states: &mut states,
                rtts: &mut rtts,
                conflicts: &mut conflicts,
                sent_times: &sent_times,
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                banner_states: None,
                banner_sender: None,
                secret: &secret,
                src,
                source_port: scan.source_port,
                syn_attempts: 1,
                now_ms: 100,
            };

            handle_tcp_reply(&syn_ack, syn_offset, syn_ihl, &mut context);
            context.now_ms = 110;
            handle_tcp_reply(&rst, rst_offset, rst_ihl, &mut context);

            assert_state(states[0], crate::TargetState::Open, 1);
            assert_eq!(read_u32(&conflicts, 0), 1);
            assert_eq!(decode_rtt_ms(&rtts, 0), Some(10.0));
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
            let mut rtts = [0; 4];
            let mut conflicts = [0; 4];
            let mut sent_times = [0; 4];
            write_u32(&mut sent_times, 0, 50);
            let targets = remote.octets();
            let ports = scan.port.to_be_bytes();
            let protocols = [crate::job::protocol_code(scan.protocol)];
            let mut context = ReplyContext {
                states: &mut states,
                rtts: &mut rtts,
                conflicts: &mut conflicts,
                sent_times: &sent_times,
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                banner_states: None,
                banner_sender: None,
                secret: &secret,
                src,
                source_port: scan.source_port,
                syn_attempts: 1,
                now_ms: 100,
            };

            handle_icmp_reply(&packet, offset, ihl, &mut context);

            assert_state(states[0], crate::TargetState::Unreachable, 1);
            assert_eq!(decode_rtt_ms(&rtts, 0), Some(50.0));
        }

        #[test]
        fn resume_enqueues_open_targets_without_done_banner_state() -> anyhow::Result<()> {
            let (sender, receiver) = std::sync::mpsc::sync_channel(4);
            let targets = [10, 0, 0, 1, 10, 0, 0, 2];
            let ports = [0, 22, 0, 22];
            let protocols = [
                crate::job::protocol_code(crate::Protocol::Ssh),
                crate::job::protocol_code(crate::Protocol::Ssh),
            ];
            let mut states = [
                crate::result::encode_state_byte(crate::TargetState::Open, 1),
                crate::result::encode_state_byte(crate::TargetState::Open, 2),
            ];
            let mut rtts = [0; 8];
            write_u32(&mut rtts, 1, 42_001);
            let mut sent_times = [0; 8];
            let mut conflicts = [0; 8];
            write_u32(&mut conflicts, 1, 3);
            let mut banner_states = [crate::job::BANNER_DONE, crate::job::BANNER_NOT_QUEUED];
            let mut buffers = ScanBuffers {
                targets: &targets,
                ports: &ports,
                protocols: &protocols,
                states: &mut states,
                rtts: &mut rtts,
                sent_times: &mut sent_times,
                conflicts: &mut conflicts,
                banner_states: &mut banner_states,
                banner_sender: &sender,
            };

            enqueue_resume_banner_targets(&mut buffers)?;
            let target = receiver.try_recv()?.expect("queued target");

            assert_eq!(target.index, 1);
            assert_eq!(target.ip, Ipv4Addr::new(10, 0, 0, 2));
            assert_eq!(target.observation.attempts, 2);
            assert_eq!(target.observation.rtt_ms, Some(42.0));
            assert_eq!(target.observation.conflicting_observations, 3);
            assert!(receiver.try_recv().is_err());
            assert_eq!(
                buffers.banner_states[1],
                crate::job::BANNER_QUEUED_OR_RUNNING
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScanSummary;
    use super::{AsyncTokenBucket, effective_runtime_limit_secs, estimate, final_checkpoint_index};
    use crate::config::{
        BudgetConfig, NetworkConfig, OutputConfig, Protocol, ScanConfig, ServiceConfig,
        SimulationConfig, SourceIp, TargetsConfig,
    };
    use crate::job::PreparedJob;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn interrupted_scan_preserves_resume_index() {
        assert_eq!(final_checkpoint_index(false, 100, 37), 37);
        assert_eq!(final_checkpoint_index(true, 100, 0), 100);
    }

    #[test]
    fn async_token_bucket_shares_reserved_budget() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let budget =
                AsyncTokenBucket::new(crate::rate::TokenBucket::new(100.0, 1.0), Instant::now());

            assert_eq!(budget.reserve(100).await, Duration::ZERO);
            assert!(budget.reserve(50).await >= Duration::from_millis(400));
            assert!(budget.reserve(50).await >= Duration::from_millis(900));
        });
    }

    #[test]
    fn estimate_reports_time_budget_bottlenecks() {
        let cfg = crate::Config {
            scan: ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![],
                syn_attempts: 3,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 512,
                banner_connects_per_second: 200,
                banner_queue_capacity: 1024,
                max_runtime_secs: None,
            },
            budget: BudgetConfig {
                time_budget_secs: Some(7_200),
                expected_open_ratio: Some(0.50),
                enforce_time_budget: false,
            },
            targets: TargetsConfig {
                include: vec![PathBuf::from("unused")],
                exclude: vec![],
                allow_private: true,
                max_targets: 10_000_000,
            },
            network: NetworkConfig {
                interface: "lo".into(),
                source_ip: SourceIp("127.0.0.1".into()),
                provider_egress_mbps: 1.0,
                application_ratio: 0.8,
                tc_ratio: 0.85,
                require_tc: false,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: PathBuf::from("."),
                output_all: false,
            },
            simulation: Default::default(),
        };

        let estimate = estimate(&cfg, 10_000_000);

        assert!(estimate.syn_seconds > 7_200.0);
        assert_eq!(estimate.expected_open, Some(5_000_000.0));
        assert!(estimate.banner_budget_capacity_open.unwrap() < 5_000_000.0);
        assert!(
            estimate
                .budget_warnings
                .iter()
                .any(|warning| warning.contains("SYN bandwidth"))
        );
        assert!(
            estimate
                .budget_warnings
                .iter()
                .any(|warning| warning.contains("banner"))
        );
    }

    #[test]
    fn effective_runtime_limit_respects_enforced_budget() {
        let mut cfg = crate::Config {
            scan: ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![],
                syn_attempts: 3,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 512,
                banner_connects_per_second: 200,
                banner_queue_capacity: 1024,
                max_runtime_secs: Some(100),
            },
            budget: BudgetConfig {
                time_budget_secs: Some(30),
                expected_open_ratio: None,
                enforce_time_budget: false,
            },
            targets: TargetsConfig {
                include: vec![PathBuf::from("unused")],
                exclude: vec![],
                allow_private: true,
                max_targets: 10,
            },
            network: NetworkConfig {
                interface: "lo".into(),
                source_ip: SourceIp("127.0.0.1".into()),
                provider_egress_mbps: 100.0,
                application_ratio: 0.8,
                tc_ratio: 0.85,
                require_tc: false,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: PathBuf::from("."),
                output_all: false,
            },
            simulation: Default::default(),
        };

        assert_eq!(effective_runtime_limit_secs(&cfg), Some(100));
        cfg.budget.enforce_time_budget = true;
        assert_eq!(effective_runtime_limit_secs(&cfg), Some(30));
        cfg.scan.max_runtime_secs = None;
        assert_eq!(effective_runtime_limit_secs(&cfg), Some(30));
    }

    #[test]
    fn simulation_scan_writes_job_events_and_summary() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let targets = temp.path().join("targets.txt");
        std::fs::write(&targets, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = crate::Config {
            scan: ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![
                    ServiceConfig {
                        port: 22,
                        protocol: Protocol::Ssh,
                    },
                    ServiceConfig {
                        port: 6379,
                        protocol: Protocol::Redis,
                    },
                ],
                syn_attempts: 3,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 512,
                banner_connects_per_second: 200,
                banner_queue_capacity: 1024,
                max_runtime_secs: None,
            },
            budget: BudgetConfig::default(),
            targets: TargetsConfig {
                include: vec![targets],
                exclude: vec![],
                allow_private: true,
                max_targets: 10,
            },
            network: NetworkConfig {
                interface: "lo".into(),
                source_ip: SourceIp("127.0.0.1".into()),
                provider_egress_mbps: 100.0,
                application_ratio: 0.8,
                tc_ratio: 0.85,
                require_tc: true,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: temp.path().join("jobs"),
                output_all: false,
            },
            simulation: SimulationConfig {
                enabled: true,
                open_ratio: 1.0,
                closed_ratio: 0.0,
                unreachable_ratio: 0.0,
                seed: "test-sim".into(),
                rtt_min_ms: 5.0,
                rtt_max_ms: 5.0,
                banner: true,
            },
        };
        let mut job = PreparedJob::create(&cfg, Some([9; 32]))?;

        let summary = super::scan(&mut job, &cfg)?;

        assert!(summary.completed);
        assert_eq!(summary.sent, 4);
        assert_eq!(summary.open, 4);
        assert_eq!(summary.banner_done, 4);
        assert_eq!(summary.banner_failed_or_incomplete, 0);
        assert_eq!(summary.pcap_drops, 0);
        assert_eq!(summary.interface_tx_packets, None);
        let events = std::fs::read_to_string(job.dir.join("events.ndjson"))?;
        assert_eq!(events.lines().count(), 4);
        assert_eq!(crate::job::export(&job.dir, false)?, 4);
        Ok(())
    }

    #[test]
    fn summary_schema_file_is_valid_json() -> anyhow::Result<()> {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/summary-v1.json"))?;

        assert_eq!(schema["title"], "RiftMap ScanSummary");
        assert_eq!(schema["properties"]["completed"]["type"], "boolean");
        Ok(())
    }

    #[test]
    fn legacy_summary_without_new_optional_fields_deserializes() -> anyhow::Result<()> {
        let summary: ScanSummary = serde_json::from_value(serde_json::json!({
            "completed": true,
            "sent": 3,
            "open": 1,
            "closed": 1,
            "unreachable": 0,
            "no_response": 1,
            "pcap_drops": 0,
            "banner_queued": 1,
            "banner_done": 1,
            "banner_failed_or_incomplete": 0,
            "timed_out": false
        }))?;

        assert_eq!(summary.syn_mss, None);
        assert_eq!(summary.conflicting_observations, 0);
        assert_eq!(summary.interface_tx_packets, None);
        Ok(())
    }
}
