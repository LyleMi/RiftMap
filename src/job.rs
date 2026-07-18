use crate::{Config, ResultV1, result::TargetState, target};
use anyhow::Context;
use memmap2::MmapMut;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
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
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("state.bin"))?;
        unsafe { MmapMut::map_mut(&f).context("map state.bin") }
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

    let targets_path = dir.join("targets.bin");
    let states_path = dir.join("state.bin");
    let target_bytes = job
        .meta
        .target_count
        .checked_mul(4)
        .context("target file length overflow")?;
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
    for _ in 0..job.meta.target_count {
        let mut target = [0; 4];
        let mut state = [0];
        targets.read_exact(&mut target)?;
        states.read_exact(&mut state)?;
        let ip = Ipv4Addr::from(u32::from_be_bytes(target));
        let id = crate::result::result_id(&job.meta.scan_id, ip, cfg.scan.port);
        let state = match state[0] {
            3 => TargetState::Open,
            2 => TargetState::Closed,
            1 => TargetState::Unreachable,
            0 => TargetState::NoResponse,
            value => anyhow::bail!("invalid target state byte {value}"),
        };
        by_id.entry(id.clone()).or_insert_with(|| ResultV1 {
            schema_version: crate::SCHEMA_VERSION,
            result_id: id,
            scan_id: job.meta.scan_id.clone(),
            ip,
            port: cfg.scan.port,
            protocol: cfg.scan.protocol,
            state,
            // A completed no-response target necessarily exhausted every
            // round. The current state format does not preserve the exact
            // response round for other outcomes, so keep their count unknown.
            syn_attempts: if state == TargetState::NoResponse {
                cfg.scan.syn_attempts
            } else {
                0
            },
            rtt_ms: None,
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
            },
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
    fn summary_round_trips_atomically() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let summary = crate::scanner::ScanSummary {
            completed: true,
            sent: 7,
            open: 1,
            closed: 2,
            unreachable: 1,
            no_response: 3,
            pcap_drops: 0,
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
