use crate::{BannerStatus, Config, Protocol, ResultV1, result::TargetState, target};
use anyhow::Context;
use memmap2::MmapMut;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMeta {
    pub format_version: u32,
    pub scan_id: String,
    pub seed_hex: String,
    pub target_count: u64,
    pub target_digest: String,
    pub shard_index: u32,
    pub shard_count: u32,
    #[serde(default)]
    pub round: u8,
    pub next_index: u64,
    pub degraded: bool,
    #[serde(default)]
    pub packets_sent: u64,
    #[serde(default)]
    pub pcap_drops: u64,
}
pub struct PreparedJob {
    pub dir: PathBuf,
    pub meta: JobMeta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
}

pub const BANNER_NOT_QUEUED: u8 = 0;
pub const BANNER_QUEUED_OR_RUNNING: u8 = 1;
pub const BANNER_DONE: u8 = 2;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut output, b| {
            write!(&mut output, "{b:02x}").expect("writing to a String cannot fail");
            output
        })
}
pub fn decode_seed(s: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "invalid seed");
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

impl PreparedJob {
    pub fn create(cfg: &Config, seed: Option<[u8; 32]>) -> anyhow::Result<Self> {
        Self::create_shard(cfg, seed, 0, 1)
    }

    pub fn create_shard(
        cfg: &Config,
        seed: Option<[u8; 32]>,
        shard_index: u32,
        shard_count: u32,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(shard_count > 0, "shard_count must be positive");
        anyhow::ensure!(
            shard_index < shard_count,
            "shard_index must be less than shard_count"
        );
        let includes = target::parse_files(&cfg.targets.include)?;
        let excludes = target::parse_files(&cfg.targets.exclude)?;
        let ranges = target::filter_allowed(
            &target::subtract(&includes, &excludes),
            cfg.targets.allow_private,
        );
        let total_count = target::count(&ranges);
        anyhow::ensure!(
            total_count > 0,
            "target set is empty after exclusions and safety policy"
        );
        let mut seed = seed.unwrap_or([0; 32]);
        if seed == [0; 32] {
            rand::rng().fill_bytes(&mut seed);
        }
        let services = cfg.scan.services();
        let total_endpoints = total_count.saturating_mul(services.len() as u64);
        anyhow::ensure!(
            total_endpoints <= cfg.targets.max_targets,
            "target count {total_endpoints} exceeds max_targets {}",
            cfg.targets.max_targets
        );
        let mut count = 0u64;
        let digest = {
            let mut h = blake3::Hasher::new();
            let mut endpoint_index = 0u64;
            for ip in target::iter(&ranges) {
                for service in &services {
                    if target_in_shard(endpoint_index, shard_index, shard_count) {
                        h.update(&ip.octets());
                        h.update(&service.port.to_be_bytes());
                        h.update(&[protocol_code(service.protocol)]);
                        count += 1;
                    }
                    endpoint_index += 1;
                }
            }
            h.finalize().to_hex().to_string()
        };
        anyhow::ensure!(
            count > 0,
            "shard {shard_index}/{shard_count} has no targets after filtering"
        );
        let mut scan_id_material = Vec::new();
        scan_id_material.extend_from_slice(&seed);
        scan_id_material.extend_from_slice(digest.as_bytes());
        scan_id_material.extend_from_slice(&shard_index.to_be_bytes());
        scan_id_material.extend_from_slice(&shard_count.to_be_bytes());
        let scan_id = hex(&blake3::hash(&scan_id_material).as_bytes()[..12]);
        let dir = cfg.output.job_root.join(&scan_id);
        fs::create_dir_all(&dir)?;
        // A materialized job no longer needs the original input paths. Avoid
        // persisting operator usernames or directory layouts in portable jobs.
        let mut snapshot = cfg.clone();
        snapshot.targets.include.clear();
        snapshot.targets.exclude.clear();
        snapshot.output.job_root = PathBuf::from(".");
        let config = toml::to_string_pretty(&snapshot)?;
        atomic_write(&dir.join("config.toml"), config.as_bytes())?;
        let mut target_writer = BufWriter::new(File::create(dir.join("targets.bin"))?);
        let mut port_writer = BufWriter::new(File::create(dir.join("ports.bin"))?);
        let mut protocol_writer = BufWriter::new(File::create(dir.join("protocols.bin"))?);
        let mut endpoint_index = 0u64;
        for ip in target::iter(&ranges) {
            for service in &services {
                if target_in_shard(endpoint_index, shard_index, shard_count) {
                    target_writer.write_all(&u32::from(ip).to_be_bytes())?;
                    port_writer.write_all(&service.port.to_be_bytes())?;
                    protocol_writer.write_all(&[protocol_code(service.protocol)])?;
                }
                endpoint_index += 1;
            }
        }
        target_writer.flush()?;
        port_writer.flush()?;
        protocol_writer.flush()?;
        let state = File::create(dir.join("state.bin"))?;
        state.set_len(count)?;
        create_zeroed_file(
            &dir.join("rtt_us.bin"),
            count.checked_mul(4).context("rtt file length overflow")?,
        )?;
        create_zeroed_file(
            &dir.join("sent_at_ms.bin"),
            count
                .checked_mul(4)
                .context("send timestamp file length overflow")?,
        )?;
        create_zeroed_file(
            &dir.join("conflicts.bin"),
            count
                .checked_mul(4)
                .context("conflict count file length overflow")?,
        )?;
        create_zeroed_file(&dir.join("banner_state.bin"), count)?;
        let meta = JobMeta {
            format_version: 1,
            scan_id,
            seed_hex: hex(&seed),
            target_count: count,
            target_digest: digest,
            shard_index,
            shard_count,
            round: 0,
            next_index: 0,
            degraded: false,
            packets_sent: 0,
            pcap_drops: 0,
        };
        save_meta(&dir, &meta)?;
        Ok(Self { dir, meta })
    }
    pub fn open(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_owned();
        let meta: JobMeta = serde_json::from_slice(&fs::read(dir.join("checkpoint.json"))?)?;
        Ok(Self { dir, meta })
    }
    pub fn target(&self, index: u64) -> anyhow::Result<Ipv4Addr> {
        anyhow::ensure!(index < self.meta.target_count, "target index out of bounds");
        let mut f = File::open(self.dir.join("targets.bin"))?;
        use std::io::{Seek, SeekFrom};
        f.seek(SeekFrom::Start(index * 4))?;
        let mut b = [0; 4];
        f.read_exact(&mut b)?;
        Ok(u32::from_be_bytes(b).into())
    }
    pub fn endpoint(&self, index: u64) -> anyhow::Result<Endpoint> {
        let ip = self.target(index)?;
        let mut port_file = File::open(self.dir.join("ports.bin"))?;
        let mut protocol_file = File::open(self.dir.join("protocols.bin"))?;
        use std::io::{Seek, SeekFrom};
        port_file.seek(SeekFrom::Start(index * 2))?;
        protocol_file.seek(SeekFrom::Start(index))?;
        let mut port = [0; 2];
        let mut protocol = [0];
        port_file.read_exact(&mut port)?;
        protocol_file.read_exact(&mut protocol)?;
        Ok(Endpoint {
            ip,
            port: u16::from_be_bytes(port),
            protocol: protocol_from_code(protocol[0])?,
        })
    }
    pub fn states(&self) -> anyhow::Result<MmapMut> {
        self.fixed_mmap("state.bin", self.meta.target_count)
            .context("map state.bin")
    }
    pub fn rtts(&self) -> anyhow::Result<MmapMut> {
        self.fixed_mmap("rtt_us.bin", self.meta.target_count * 4)
            .context("map rtt_us.bin")
    }
    pub fn sent_times(&self) -> anyhow::Result<MmapMut> {
        self.fixed_mmap("sent_at_ms.bin", self.meta.target_count * 4)
            .context("map sent_at_ms.bin")
    }
    pub fn conflicts(&self) -> anyhow::Result<MmapMut> {
        self.fixed_mmap("conflicts.bin", self.meta.target_count * 4)
            .context("map conflicts.bin")
    }
    pub fn banner_states(&self) -> anyhow::Result<MmapMut> {
        self.fixed_mmap("banner_state.bin", self.meta.target_count)
            .context("map banner_state.bin")
    }
    pub fn ensure_endpoint_files(&self, cfg: &Config) -> anyhow::Result<()> {
        let ports = self.dir.join("ports.bin");
        let protocols = self.dir.join("protocols.bin");
        if !ports.exists() {
            let mut writer = BufWriter::new(File::create(&ports)?);
            for _ in 0..self.meta.target_count {
                writer.write_all(&cfg.scan.port.to_be_bytes())?;
            }
            writer.flush()?;
        }
        if !protocols.exists() {
            let mut writer = BufWriter::new(File::create(&protocols)?);
            for _ in 0..self.meta.target_count {
                writer.write_all(&[protocol_code(cfg.scan.protocol)])?;
            }
            writer.flush()?;
        }
        anyhow::ensure!(
            fs::metadata(&ports)?.len() == self.meta.target_count * 2,
            "ports.bin length does not match checkpoint target_count"
        );
        anyhow::ensure!(
            fs::metadata(&protocols)?.len() == self.meta.target_count,
            "protocols.bin length does not match checkpoint target_count"
        );
        Ok(())
    }
    fn fixed_mmap(&self, name: &str, len: u64) -> anyhow::Result<MmapMut> {
        let path = self.dir.join(name);
        create_fixed_file(&path, len)?;
        let f = OpenOptions::new().read(true).write(true).open(path)?;
        unsafe { Ok(MmapMut::map_mut(&f)?) }
    }
    pub fn checkpoint(&mut self, next: u64) -> anyhow::Result<()> {
        self.meta.next_index = next;
        save_meta(&self.dir, &self.meta)
    }
}

fn target_in_shard(index: u64, shard_index: u32, shard_count: u32) -> bool {
    index % u64::from(shard_count) == u64::from(shard_index)
}

pub(crate) fn protocol_code(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Ssh => 1,
        Protocol::Ftp => 2,
        Protocol::Mysql => 3,
        Protocol::Smtp => 4,
        Protocol::Redis => 5,
        Protocol::Postgres => 6,
    }
}

pub(crate) fn protocol_from_code(code: u8) -> anyhow::Result<Protocol> {
    Ok(match code {
        1 => Protocol::Ssh,
        2 => Protocol::Ftp,
        3 => Protocol::Mysql,
        4 => Protocol::Smtp,
        5 => Protocol::Redis,
        6 => Protocol::Postgres,
        _ => anyhow::bail!("invalid protocol code {code}"),
    })
}

fn save_meta(dir: &Path, meta: &JobMeta) -> anyhow::Result<()> {
    atomic_write(
        &dir.join("checkpoint.json"),
        &serde_json::to_vec_pretty(meta)?,
    )
}
fn atomic_write(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn create_fixed_file(path: &Path, len: u64) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    if file.metadata()?.len() != len {
        file.set_len(len)?;
    }
    Ok(())
}

fn create_zeroed_file(path: &Path, len: u64) -> anyhow::Result<()> {
    let file = File::create(path)?;
    file.set_len(len)?;
    Ok(())
}

pub fn save_summary(dir: &Path, summary: &crate::scanner::ScanSummary) -> anyhow::Result<()> {
    atomic_write(
        &dir.join("summary.json"),
        &serde_json::to_vec_pretty(summary)?,
    )
}

pub fn load_summary(dir: &Path) -> anyhow::Result<crate::scanner::ScanSummary> {
    Ok(serde_json::from_slice(&fs::read(
        dir.join("summary.json"),
    )?)?)
}

pub fn append_event(dir: &Path, result: &ResultV1) -> anyhow::Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("events.ndjson"))?;
    serde_json::to_writer(&mut f, result)?;
    f.write_all(b"\n")?;
    f.sync_data()?;
    Ok(())
}

pub fn ensure_banner_state_backfilled(job: &PreparedJob, cfg: &Config) -> anyhow::Result<MmapMut> {
    let path = job.dir.join("banner_state.bin");
    let existed = path.exists();
    let mut states = job.banner_states()?;
    if !existed {
        backfill_banner_done_from_events(job, cfg, &mut states)?;
        states.flush()?;
    }
    Ok(states)
}

pub fn backfill_banner_done_from_events(
    job: &PreparedJob,
    cfg: &Config,
    banner_states: &mut [u8],
) -> anyhow::Result<()> {
    job.ensure_endpoint_files(cfg)?;
    let input = job.dir.join("events.ndjson");
    if !input.exists() {
        return Ok(());
    }
    for (i, line) in BufReader::new(File::open(input)?).lines().enumerate() {
        let line = line?;
        let result: ResultV1 =
            serde_json::from_str(&line).with_context(|| format!("event line {}", i + 1))?;
        if result.scan_id != job.meta.scan_id {
            continue;
        }
        let index = endpoint_index(&job.dir, job.meta.target_count, result.ip, result.port)?;
        banner_states[index] = BANNER_DONE;
    }
    Ok(())
}

fn endpoint_index(dir: &Path, target_count: u64, ip: Ipv4Addr, port: u16) -> anyhow::Result<usize> {
    let mut target_file = File::open(dir.join("targets.bin"))?;
    let mut port_file = File::open(dir.join("ports.bin"))?;
    let needle = u32::from(ip).to_be_bytes();
    let mut lo = 0u64;
    let mut hi = target_count;
    while lo < hi {
        let mid = (lo + hi) / 2;
        use std::io::{Seek, SeekFrom};
        target_file.seek(SeekFrom::Start(mid * 4))?;
        let mut value = [0; 4];
        target_file.read_exact(&mut value)?;
        if value < needle {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    while lo < target_count {
        target_file.seek(std::io::SeekFrom::Start(lo * 4))?;
        let mut value = [0; 4];
        target_file.read_exact(&mut value)?;
        if value != needle {
            break;
        }
        port_file.seek(std::io::SeekFrom::Start(lo * 2))?;
        let mut candidate_port = [0; 2];
        port_file.read_exact(&mut candidate_port)?;
        if u16::from_be_bytes(candidate_port) == port {
            return Ok(lo as usize);
        }
        lo += 1;
    }
    anyhow::bail!("event endpoint {ip}:{port} not found in job targets")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Ndjson,
    Csv,
}

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    pub output_all: bool,
    pub state: Option<TargetState>,
    pub protocol: Option<Protocol>,
    pub banner_status: Option<BannerStatus>,
}

impl ExportOptions {
    fn includes(&self, result: &ResultV1) -> bool {
        if !self.output_all && result.state != TargetState::Open {
            return false;
        }
        if self.state.is_some_and(|state| result.state != state) {
            return false;
        }
        if self
            .protocol
            .is_some_and(|protocol| result.protocol != protocol)
        {
            return false;
        }
        if self
            .banner_status
            .is_some_and(|status| result.banner_status != Some(status))
        {
            return false;
        }
        true
    }
}

pub fn export(dir: &Path, output_all: bool) -> anyhow::Result<usize> {
    export_with_options(
        dir,
        &ExportOptions {
            output_all,
            ..Default::default()
        },
        ExportFormat::Ndjson,
    )
}

pub fn export_with_options(
    dir: &Path,
    options: &ExportOptions,
    format: ExportFormat,
) -> anyhow::Result<usize> {
    let cfg = Config::load(dir.join("config.toml")).context("load immutable job config")?;
    let job = PreparedJob::open(dir).context("load job checkpoint")?;
    job.ensure_endpoint_files(&cfg)?;
    let input = dir.join("events.ndjson");
    let mut by_id: BTreeMap<String, ResultV1> = BTreeMap::new();
    if input.exists() {
        for (i, line) in BufReader::new(File::open(input)?).lines().enumerate() {
            let line = line?;
            let r: ResultV1 =
                serde_json::from_str(&line).with_context(|| format!("event line {}", i + 1))?;
            by_id.insert(r.result_id.clone(), r);
        }
    }
    if options.output_all {
        synthesize_missing_results(dir, &mut by_id)?;
    }
    let mut selected = Vec::new();
    for result in by_id.into_values() {
        if options.includes(&result) {
            selected.push(result);
        }
    }
    let output = match format {
        ExportFormat::Ndjson => dir.join("results.ndjson"),
        ExportFormat::Csv => dir.join("results.csv"),
    };
    let mut out = BufWriter::new(File::create(output)?);
    match format {
        ExportFormat::Ndjson => write_ndjson(&mut out, &selected)?,
        ExportFormat::Csv => write_csv(&mut out, &selected)?,
    }
    out.flush()?;
    Ok(selected.len())
}

fn write_ndjson(out: &mut impl Write, results: &[ResultV1]) -> anyhow::Result<()> {
    for result in results {
        serde_json::to_writer(&mut *out, result)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

fn write_csv(out: &mut impl Write, results: &[ResultV1]) -> anyhow::Result<()> {
    writeln!(
        out,
        "schema_version,result_id,scan_id,ip,port,protocol,state,syn_attempts,rtt_ms,conflicting_observations,first_observed_at,last_observed_at,banner_status,banner_base64,banner_text,ssh,ftp,mysql,smtp,redis,postgres"
    )?;
    for result in results {
        write_csv_record(out, result)?;
    }
    Ok(())
}

fn write_csv_record(out: &mut impl Write, result: &ResultV1) -> anyhow::Result<()> {
    let fields = [
        result.schema_version.to_string(),
        result.result_id.clone(),
        result.scan_id.clone(),
        result.ip.to_string(),
        result.port.to_string(),
        serde_plain(result.protocol)?,
        serde_plain(result.state)?,
        result.syn_attempts.to_string(),
        result
            .rtt_ms
            .map(|value| value.to_string())
            .unwrap_or_default(),
        result.conflicting_observations.to_string(),
        result.first_observed_at.clone().unwrap_or_default(),
        result.last_observed_at.clone().unwrap_or_default(),
        result
            .banner_status
            .map(serde_plain)
            .transpose()?
            .unwrap_or_default(),
        result.banner_base64.clone().unwrap_or_default(),
        result.banner_text.clone().unwrap_or_default(),
        option_json(&result.ssh)?,
        option_json(&result.ftp)?,
        option_json(&result.mysql)?,
        option_json(&result.smtp)?,
        option_json(&result.redis)?,
        option_json(&result.postgres)?,
    ];
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        write_csv_field(out, field)?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

fn serde_plain<T: Serialize>(value: T) -> anyhow::Result<String> {
    let json = serde_json::to_string(&value)?;
    Ok(json.trim_matches('"').to_owned())
}

fn option_json<T: Serialize>(value: &Option<T>) -> anyhow::Result<String> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map(|value| value.unwrap_or_default())
        .map_err(Into::into)
}

fn write_csv_field(out: &mut impl Write, field: &str) -> anyhow::Result<()> {
    if field.contains([',', '"', '\n', '\r']) {
        out.write_all(b"\"")?;
        for byte in field.bytes() {
            if byte == b'"' {
                out.write_all(b"\"\"")?;
            } else {
                out.write_all(&[byte])?;
            }
        }
        out.write_all(b"\"")?;
    } else {
        out.write_all(field.as_bytes())?;
    }
    Ok(())
}

fn synthesize_missing_results(
    dir: &Path,
    by_id: &mut BTreeMap<String, ResultV1>,
) -> anyhow::Result<()> {
    let cfg = Config::load(dir.join("config.toml")).context("load immutable job config")?;
    let job = PreparedJob::open(dir).context("load job checkpoint")?;
    anyhow::ensure!(
        job.meta.round >= cfg.scan.syn_attempts,
        "cannot export all targets before the scan has completed"
    );
    anyhow::ensure!(
        !job.meta.degraded && job.meta.pcap_drops == 0,
        "cannot export all targets from a degraded scan with pcap drops"
    );

    let targets_path = dir.join("targets.bin");
    let ports_path = dir.join("ports.bin");
    let protocols_path = dir.join("protocols.bin");
    let states_path = dir.join("state.bin");
    let rtts_path = dir.join("rtt_us.bin");
    let conflicts_path = dir.join("conflicts.bin");
    let target_bytes = job
        .meta
        .target_count
        .checked_mul(4)
        .context("target file length overflow")?;
    create_fixed_file(&rtts_path, target_bytes)?;
    create_fixed_file(&conflicts_path, target_bytes)?;
    anyhow::ensure!(
        fs::metadata(&targets_path)?.len() == target_bytes,
        "targets.bin length does not match checkpoint target_count"
    );
    anyhow::ensure!(
        fs::metadata(&ports_path)?.len() == job.meta.target_count * 2,
        "ports.bin length does not match checkpoint target_count"
    );
    anyhow::ensure!(
        fs::metadata(&protocols_path)?.len() == job.meta.target_count,
        "protocols.bin length does not match checkpoint target_count"
    );
    anyhow::ensure!(
        fs::metadata(&states_path)?.len() == job.meta.target_count,
        "state.bin length does not match checkpoint target_count"
    );

    let mut targets = BufReader::new(File::open(targets_path)?);
    let mut ports = BufReader::new(File::open(ports_path)?);
    let mut protocols = BufReader::new(File::open(protocols_path)?);
    let mut states = BufReader::new(File::open(states_path)?);
    let mut rtts = BufReader::new(File::open(rtts_path)?);
    let mut conflicts = BufReader::new(File::open(conflicts_path)?);
    for _ in 0..job.meta.target_count {
        let mut target = [0; 4];
        let mut port = [0; 2];
        let mut protocol = [0];
        let mut state = [0];
        let mut rtt = [0; 4];
        let mut conflict_count = [0; 4];
        targets.read_exact(&mut target)?;
        ports.read_exact(&mut port)?;
        protocols.read_exact(&mut protocol)?;
        states.read_exact(&mut state)?;
        rtts.read_exact(&mut rtt)?;
        conflicts.read_exact(&mut conflict_count)?;
        let ip = Ipv4Addr::from(u32::from_be_bytes(target));
        let port = u16::from_be_bytes(port);
        let protocol = protocol_from_code(protocol[0])?;
        let id = crate::result::result_id(&job.meta.scan_id, ip, port, protocol);
        let (state, observed_attempts) = crate::result::decode_state_byte(state[0])?;
        let rtt_ms = decode_rtt_ms(rtt);
        let conflicting_observations = u32::from_le_bytes(conflict_count);
        by_id.entry(id.clone()).or_insert_with(|| ResultV1 {
            schema_version: crate::SCHEMA_VERSION,
            result_id: id,
            scan_id: job.meta.scan_id.clone(),
            ip,
            port,
            protocol,
            state,
            syn_attempts: if state == TargetState::NoResponse {
                cfg.scan.syn_attempts
            } else {
                observed_attempts
            },
            rtt_ms,
            conflicting_observations,
            first_observed_at: None,
            last_observed_at: None,
            banner_status: None,
            banner_base64: None,
            banner_text: None,
            ssh: None,
            ftp: None,
            mysql: None,
            smtp: None,
            redis: None,
            postgres: None,
        });
    }
    Ok(())
}

fn decode_rtt_ms(raw: [u8; 4]) -> Option<f64> {
    let stored = u32::from_le_bytes(raw);
    (stored != 0).then(|| f64::from(stored - 1) / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        NetworkConfig, OutputConfig, Protocol, ScanConfig, SourceIp, TargetsConfig,
    };

    fn config(root: &Path, include: PathBuf, output_all: bool) -> Config {
        Config {
            scan: ScanConfig {
                port: 22,
                protocol: Protocol::Ssh,
                services: vec![],
                syn_attempts: 3,
                source_port: 61_000,
                syn_ttl: crate::config::d_syn_ttl(),
                syn_window_size: crate::config::d_syn_window_size(),
                syn_window_scale: crate::config::d_syn_window_scale(),
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 8,
                banner_connects_per_second: 10,
                banner_queue_capacity: 128,
                max_runtime_secs: None,
                ssh: Default::default(),
            },
            budget: Default::default(),
            targets: TargetsConfig {
                include: vec![include],
                exclude: vec![],
                allow_private: true,
                max_targets: 10,
            },
            network: NetworkConfig {
                interface: "lo".into(),
                source_ip: SourceIp("127.0.0.1".into()),
                provider_egress_mbps: 100.0,
                application_ratio: 0.8,
                dynamic_application_mbps_file: None,
                tc_ratio: 0.85,
                require_tc: false,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: root.into(),
                output_all,
            },
            simulation: Default::default(),
        }
    }

    fn open_result(job: &PreparedJob, cfg: &Config, ip: Ipv4Addr, text: &str) -> ResultV1 {
        ResultV1 {
            schema_version: crate::SCHEMA_VERSION,
            result_id: crate::result::result_id(
                &job.meta.scan_id,
                ip,
                cfg.scan.port,
                cfg.scan.protocol,
            ),
            scan_id: job.meta.scan_id.clone(),
            ip,
            port: cfg.scan.port,
            protocol: cfg.scan.protocol,
            state: TargetState::Open,
            syn_attempts: 1,
            rtt_ms: Some(1.0),
            conflicting_observations: 0,
            first_observed_at: Some("1720000000000".into()),
            last_observed_at: Some("1720000000000".into()),
            banner_status: Some(crate::BannerStatus::Ok),
            banner_base64: None,
            banner_text: Some(text.into()),
            ssh: None,
            ftp: None,
            mysql: None,
            smtp: None,
            redis: None,
            postgres: None,
        }
    }

    #[test]
    fn output_all_synthesizes_targets_without_events() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")?;
        let cfg = config(temp.path(), include, true);
        let mut job = PreparedJob::create(&cfg, Some([1; 32]))?;
        {
            let mut states = job.states()?;
            states.copy_from_slice(&[0, 1, 2]);
            states.flush()?;
        }
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;

        assert_eq!(export(&job.dir, true)?, 3);
        let results: Vec<ResultV1> = fs::read_to_string(job.dir.join("results.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(results.len(), 3);
        let states: BTreeMap<_, _> = results.into_iter().map(|r| (r.ip, r.state)).collect();
        assert_eq!(states[&"10.0.0.1".parse()?], TargetState::NoResponse);
        assert_eq!(states[&"10.0.0.2".parse()?], TargetState::Unreachable);
        assert_eq!(states[&"10.0.0.3".parse()?], TargetState::Closed);
        Ok(())
    }

    #[test]
    fn create_shard_materializes_only_selected_targets() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(
            &include,
            "10.0.0.1\n10.0.0.2\n10.0.0.3\n10.0.0.4\n10.0.0.5\n",
        )?;
        let cfg = config(temp.path(), include, false);

        let job = PreparedJob::create_shard(&cfg, Some([8; 32]), 1, 2)?;

        assert_eq!(job.meta.shard_index, 1);
        assert_eq!(job.meta.shard_count, 2);
        assert_eq!(job.meta.target_count, 2);
        assert_eq!(job.target(0)?, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(job.target(1)?, Ipv4Addr::new(10, 0, 0, 4));
        assert!(job.target(2).is_err());
        Ok(())
    }

    #[test]
    fn create_job_materializes_multiple_services_as_endpoints() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let mut cfg = config(temp.path(), include, false);
        cfg.scan.services = vec![
            crate::config::ServiceConfig {
                port: 22,
                protocol: Protocol::Ssh,
            },
            crate::config::ServiceConfig {
                port: 25,
                protocol: Protocol::Smtp,
            },
        ];

        let job = PreparedJob::create(&cfg, Some([10; 32]))?;

        assert_eq!(job.meta.target_count, 4);
        assert_eq!(
            job.endpoint(0)?,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 22,
                protocol: Protocol::Ssh
            }
        );
        assert_eq!(
            job.endpoint(1)?,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 1),
                port: 25,
                protocol: Protocol::Smtp
            }
        );
        assert_eq!(
            job.endpoint(3)?,
            Endpoint {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                port: 25,
                protocol: Protocol::Smtp
            }
        );
        Ok(())
    }

    #[test]
    fn create_shard_rejects_invalid_or_empty_shards() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, false);

        let invalid = match PreparedJob::create_shard(&cfg, Some([9; 32]), 2, 2) {
            Ok(_) => anyhow::bail!("invalid shard unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(invalid.to_string().contains("less than shard_count"));

        let empty = match PreparedJob::create_shard(&cfg, Some([9; 32]), 1, 2) {
            Ok(_) => anyhow::bail!("empty shard unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(empty.to_string().contains("has no targets"));
        Ok(())
    }

    #[test]
    fn output_all_preserves_observed_syn_attempts() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = config(temp.path(), include, true);
        let mut job = PreparedJob::create(&cfg, Some([4; 32]))?;
        {
            let mut states = job.states()?;
            states.copy_from_slice(&[
                crate::result::encode_state_byte(TargetState::Unreachable, 1),
                crate::result::encode_state_byte(TargetState::Closed, 2),
            ]);
            states.flush()?;
            let mut rtts = job.rtts()?;
            rtts[..4].copy_from_slice(&12_501u32.to_le_bytes());
            rtts[4..8].copy_from_slice(&34_001u32.to_le_bytes());
            rtts.flush()?;
            let mut conflicts = job.conflicts()?;
            conflicts[4..8].copy_from_slice(&1u32.to_le_bytes());
            conflicts.flush()?;
        }
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;

        assert_eq!(export(&job.dir, true)?, 2);
        let results: Vec<ResultV1> = fs::read_to_string(job.dir.join("results.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        let attempts: BTreeMap<_, _> = results
            .iter()
            .map(|result| (result.state, result.syn_attempts))
            .collect();
        assert_eq!(attempts[&TargetState::Unreachable], 1);
        assert_eq!(attempts[&TargetState::Closed], 2);
        let rtts: BTreeMap<_, _> = results
            .iter()
            .map(|result| (result.state, result.rtt_ms))
            .collect();
        assert_eq!(rtts[&TargetState::Unreachable], Some(12.5));
        assert_eq!(rtts[&TargetState::Closed], Some(34.0));
        let conflicts: BTreeMap<_, _> = results
            .iter()
            .map(|result| (result.state, result.conflicting_observations))
            .collect();
        assert_eq!(conflicts[&TargetState::Unreachable], 0);
        assert_eq!(conflicts[&TargetState::Closed], 1);
        Ok(())
    }

    #[test]
    fn output_all_synthesizes_each_service_endpoint() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let mut cfg = config(temp.path(), include, true);
        cfg.scan.services = vec![
            crate::config::ServiceConfig {
                port: 22,
                protocol: Protocol::Ssh,
            },
            crate::config::ServiceConfig {
                port: 25,
                protocol: Protocol::Smtp,
            },
        ];
        let mut job = PreparedJob::create(&cfg, Some([11; 32]))?;
        {
            let mut states = job.states()?;
            states.copy_from_slice(&[
                crate::result::encode_state_byte(TargetState::Open, 1),
                crate::result::encode_state_byte(TargetState::Closed, 1),
                crate::result::encode_state_byte(TargetState::NoResponse, 0),
                crate::result::encode_state_byte(TargetState::Unreachable, 2),
            ]);
            states.flush()?;
        }
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;

        assert_eq!(export(&job.dir, true)?, 4);
        let results: Vec<ResultV1> = fs::read_to_string(job.dir.join("results.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        let endpoints: BTreeMap<_, _> = results
            .into_iter()
            .map(|result| ((result.ip, result.port), (result.protocol, result.state)))
            .collect();
        assert_eq!(
            endpoints[&(Ipv4Addr::new(10, 0, 0, 1), 22)],
            (Protocol::Ssh, TargetState::Open)
        );
        assert_eq!(
            endpoints[&(Ipv4Addr::new(10, 0, 0, 1), 25)],
            (Protocol::Smtp, TargetState::Closed)
        );
        assert_eq!(
            endpoints[&(Ipv4Addr::new(10, 0, 0, 2), 22)],
            (Protocol::Ssh, TargetState::NoResponse)
        );
        assert_eq!(
            endpoints[&(Ipv4Addr::new(10, 0, 0, 2), 25)],
            (Protocol::Smtp, TargetState::Unreachable)
        );
        Ok(())
    }

    #[test]
    fn output_all_rejects_incomplete_scan() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, true);
        let job = PreparedJob::create(&cfg, Some([2; 32]))?;

        let error = export(&job.dir, true).unwrap_err();
        assert!(error.to_string().contains("before the scan has completed"));
        Ok(())
    }

    #[test]
    fn output_all_rejects_degraded_scan() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, true);
        let mut job = PreparedJob::create(&cfg, Some([3; 32]))?;
        job.meta.round = cfg.scan.syn_attempts;
        job.meta.degraded = true;
        job.meta.pcap_drops = 1;
        job.checkpoint(job.meta.target_count)?;

        let error = export(&job.dir, true).unwrap_err();
        assert!(error.to_string().contains("degraded scan"));
        Ok(())
    }

    #[test]
    fn export_filters_by_state_and_banner_status() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")?;
        let cfg = config(temp.path(), include, true);
        let mut job = PreparedJob::create(&cfg, Some([6; 32]))?;
        {
            let mut states = job.states()?;
            states.copy_from_slice(&[
                crate::result::encode_state_byte(TargetState::Open, 1),
                crate::result::encode_state_byte(TargetState::Closed, 2),
                crate::result::encode_state_byte(TargetState::NoResponse, 0),
            ]);
            states.flush()?;
        }
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;
        append_event(
            &job.dir,
            &open_result(&job, &cfg, "10.0.0.1".parse()?, "SSH-2.0-OpenSSH_9.6"),
        )?;

        let closed = ExportOptions {
            output_all: true,
            state: Some(TargetState::Closed),
            ..Default::default()
        };
        assert_eq!(
            export_with_options(&job.dir, &closed, ExportFormat::Ndjson)?,
            1
        );
        let results: Vec<ResultV1> = fs::read_to_string(job.dir.join("results.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(results[0].state, TargetState::Closed);

        let ok_banners = ExportOptions {
            output_all: true,
            banner_status: Some(crate::BannerStatus::Ok),
            ..Default::default()
        };
        assert_eq!(
            export_with_options(&job.dir, &ok_banners, ExportFormat::Ndjson)?,
            1
        );
        let results: Vec<ResultV1> = fs::read_to_string(job.dir.join("results.ndjson"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(results[0].ip, Ipv4Addr::new(10, 0, 0, 1));
        Ok(())
    }

    #[test]
    fn export_writes_csv_with_escaped_fields() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, false);
        let job = PreparedJob::create(&cfg, Some([7; 32]))?;
        append_event(
            &job.dir,
            &open_result(&job, &cfg, "10.0.0.1".parse()?, "hello, \"ssh\""),
        )?;

        assert_eq!(
            export_with_options(&job.dir, &ExportOptions::default(), ExportFormat::Csv)?,
            1
        );
        let csv = fs::read_to_string(job.dir.join("results.csv"))?;
        assert!(csv.starts_with("schema_version,result_id,scan_id,ip,port,protocol,state"));
        assert!(csv.contains("\"hello, \"\"ssh\"\"\""));
        assert!(!job.dir.join("results.ndjson").exists());
        Ok(())
    }

    #[test]
    fn missing_banner_state_is_backfilled_from_events() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = config(temp.path(), include, false);
        let job = PreparedJob::create(&cfg, Some([5; 32]))?;
        let ip = "10.0.0.2".parse()?;
        append_event(
            &job.dir,
            &ResultV1 {
                schema_version: crate::SCHEMA_VERSION,
                result_id: crate::result::result_id(
                    &job.meta.scan_id,
                    ip,
                    cfg.scan.port,
                    cfg.scan.protocol,
                ),
                scan_id: job.meta.scan_id.clone(),
                ip,
                port: cfg.scan.port,
                protocol: cfg.scan.protocol,
                state: TargetState::Open,
                syn_attempts: 1,
                rtt_ms: Some(1.0),
                conflicting_observations: 0,
                first_observed_at: None,
                last_observed_at: None,
                banner_status: Some(crate::BannerStatus::Ok),
                banner_base64: None,
                banner_text: None,
                ssh: None,
                ftp: None,
                mysql: None,
                smtp: None,
                redis: None,
                postgres: None,
            },
        )?;
        fs::remove_file(job.dir.join("banner_state.bin"))?;

        let states = ensure_banner_state_backfilled(&job, &cfg)?;

        assert_eq!(states[0], BANNER_NOT_QUEUED);
        assert_eq!(states[1], BANNER_DONE);
        Ok(())
    }

    #[test]
    fn summary_round_trips_atomically() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let summary = crate::scanner::ScanSummary {
            completed: true,
            sent: 7,
            syn_mss: Some(1460),
            open: 1,
            closed: 2,
            unreachable: 1,
            no_response: 3,
            pcap_drops: 0,
            conflicting_observations: 2,
            interface_tx_packets: Some(11),
            interface_tx_bytes: Some(990),
            banner_queued: 1,
            banner_done: 1,
            banner_failed_or_incomplete: 0,
            timed_out: false,
        };

        save_summary(temp.path(), &summary)?;

        assert_eq!(load_summary(temp.path())?, summary);
        assert!(!temp.path().join("summary.tmp").exists());
        Ok(())
    }

    #[test]
    fn old_checkpoint_defaults_cumulative_counters() -> anyhow::Result<()> {
        let meta: JobMeta = serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "scan_id": "scan",
            "seed_hex": "00".repeat(32),
            "target_count": 1,
            "target_digest": "digest",
            "shard_index": 0,
            "shard_count": 1,
            "next_index": 0,
            "degraded": false
        }))?;

        assert_eq!(meta.packets_sent, 0);
        assert_eq!(meta.pcap_drops, 0);
        Ok(())
    }
}
