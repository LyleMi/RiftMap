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
