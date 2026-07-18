use crate::{Config, ResultV1, result::TargetState, target};
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
        let includes = target::parse_files(&cfg.targets.include)?;
        let excludes = target::parse_files(&cfg.targets.exclude)?;
        let ranges = target::filter_allowed(
            &target::subtract(&includes, &excludes),
            cfg.targets.allow_private,
        );
        let count = target::count(&ranges);
        anyhow::ensure!(
            count > 0,
            "target set is empty after exclusions and safety policy"
        );
        anyhow::ensure!(
            count <= cfg.targets.max_targets,
            "target count {count} exceeds max_targets {}",
            cfg.targets.max_targets
        );
        let mut seed = seed.unwrap_or([0; 32]);
        if seed == [0; 32] {
            rand::rng().fill_bytes(&mut seed);
        }
        let digest = {
            let mut h = blake3::Hasher::new();
            for ip in target::iter(&ranges) {
                h.update(&ip.octets());
            }
            h.finalize().to_hex().to_string()
        };
        let scan_id = hex(&blake3::hash(&[&seed[..], digest.as_bytes()].concat()).as_bytes()[..12]);
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
        let mut writer = BufWriter::new(File::create(dir.join("targets.bin"))?);
        for ip in target::iter(&ranges) {
            writer.write_all(&u32::from(ip).to_be_bytes())?;
        }
        writer.flush()?;
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
            shard_index: 0,
            shard_count: 1,
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
    let input = job.dir.join("events.ndjson");
    if !input.exists() {
        return Ok(());
    }
    for (i, line) in BufReader::new(File::open(input)?).lines().enumerate() {
        let line = line?;
        let result: ResultV1 =
            serde_json::from_str(&line).with_context(|| format!("event line {}", i + 1))?;
        if result.scan_id != job.meta.scan_id || result.port != cfg.scan.port {
            continue;
        }
        let index = target_index(&job.dir, job.meta.target_count, result.ip)?;
        banner_states[index] = BANNER_DONE;
    }
    Ok(())
}

fn target_index(dir: &Path, target_count: u64, ip: Ipv4Addr) -> anyhow::Result<usize> {
    let mut file = File::open(dir.join("targets.bin"))?;
    let needle = u32::from(ip).to_be_bytes();
    let mut lo = 0u64;
    let mut hi = target_count;
    while lo < hi {
        let mid = (lo + hi) / 2;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(mid * 4))?;
        let mut value = [0; 4];
        file.read_exact(&mut value)?;
        if value < needle {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    anyhow::ensure!(lo < target_count, "event target not found in job targets");
    file.seek(std::io::SeekFrom::Start(lo * 4))?;
    let mut value = [0; 4];
    file.read_exact(&mut value)?;
    anyhow::ensure!(value == needle, "event target not found in job targets");
    Ok(lo as usize)
}

pub fn export(dir: &Path, output_all: bool) -> anyhow::Result<usize> {
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
    if output_all {
        synthesize_missing_results(dir, &mut by_id)?;
    }
    let mut out = BufWriter::new(File::create(dir.join("results.ndjson"))?);
    let mut n = 0;
    for r in by_id.into_values() {
        if output_all || r.state == TargetState::Open {
            serde_json::to_writer(&mut out, &r)?;
            out.write_all(b"\n")?;
            n += 1;
        }
    }
    out.flush()?;
    Ok(n)
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
        fs::metadata(&states_path)?.len() == job.meta.target_count,
        "state.bin length does not match checkpoint target_count"
    );

    let mut targets = BufReader::new(File::open(targets_path)?);
    let mut states = BufReader::new(File::open(states_path)?);
    let mut rtts = BufReader::new(File::open(rtts_path)?);
    let mut conflicts = BufReader::new(File::open(conflicts_path)?);
    for _ in 0..job.meta.target_count {
        let mut target = [0; 4];
        let mut state = [0];
        let mut rtt = [0; 4];
        let mut conflict_count = [0; 4];
        targets.read_exact(&mut target)?;
        states.read_exact(&mut state)?;
        rtts.read_exact(&mut rtt)?;
        conflicts.read_exact(&mut conflict_count)?;
        let ip = Ipv4Addr::from(u32::from_be_bytes(target));
        let id = crate::result::result_id(&job.meta.scan_id, ip, cfg.scan.port);
        let (state, observed_attempts) = crate::result::decode_state_byte(state[0])?;
        let rtt_ms = decode_rtt_ms(rtt);
        let conflicting_observations = u32::from_le_bytes(conflict_count);
        by_id.entry(id.clone()).or_insert_with(|| ResultV1 {
            schema_version: crate::SCHEMA_VERSION,
            result_id: id,
            scan_id: job.meta.scan_id.clone(),
            ip,
            port: cfg.scan.port,
            protocol: cfg.scan.protocol,
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
                syn_attempts: 3,
                source_port: 61_000,
                connect_timeout_ms: 3_000,
                banner_timeout_ms: 5_000,
                banner_max_bytes: 4_096,
                banner_attempts: 2,
                banner_concurrency: 8,
                banner_connects_per_second: 10,
                banner_queue_capacity: 128,
                max_runtime_secs: None,
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
                tc_ratio: 0.85,
                require_tc: false,
                accounting: "estimated-wire".into(),
            },
            output: OutputConfig {
                job_root: root.into(),
                output_all,
            },
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
                result_id: crate::result::result_id(&job.meta.scan_id, ip, cfg.scan.port),
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
