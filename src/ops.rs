use crate::{
    Config,
    job::{self, JobMeta, PreparedJob},
    result::{self, TargetState},
    scanner::{self, Estimate, ScanSummary},
    target,
};
use anyhow::Context;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Serialize)]
pub struct TargetReport {
    pub include_file_count: usize,
    pub exclude_file_count: usize,
    pub target_count: u64,
}

#[derive(Debug, Serialize)]
pub struct ConfigValidationReport {
    pub target_report: TargetReport,
    pub estimate: Estimate,
    pub job_root: PathBuf,
    pub allow_private: bool,
    pub max_targets: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StateCounters {
    pub open: u64,
    pub closed: u64,
    pub unreachable: u64,
    pub no_response: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BannerCounters {
    pub queued: u64,
    pub done: u64,
    pub failed_or_incomplete: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextAction {
    Export,
    Resume,
    ReviewDegradedExport,
    InspectMissingSummary,
}

impl NextAction {
    pub fn as_str(self) -> &'static str {
        match self {
            NextAction::Export => "export",
            NextAction::Resume => "resume",
            NextAction::ReviewDegradedExport => "review_degraded_export",
            NextAction::InspectMissingSummary => "inspect_missing_summary",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JobStatus {
    pub scan_id: String,
    pub job_dir: PathBuf,
    pub target_count: u64,
    pub round: u8,
    pub syn_attempts: u8,
    pub next_index: u64,
    pub progress_percent: f64,
    pub summary_present: bool,
    pub completed: bool,
    pub timed_out: bool,
    pub degraded: bool,
    pub pcap_drops: u64,
    pub sent: u64,
    pub states: StateCounters,
    pub banners: BannerCounters,
    pub next_action: NextAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobListStatus {
    Completed,
    TimedOut,
    Degraded,
    RunningOrInterrupted,
    MissingSummary,
    Invalid,
}

impl JobListStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            JobListStatus::Completed => "completed",
            JobListStatus::TimedOut => "timed_out",
            JobListStatus::Degraded => "degraded",
            JobListStatus::RunningOrInterrupted => "running_or_interrupted",
            JobListStatus::MissingSummary => "missing_summary",
            JobListStatus::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct JobListEntry {
    pub scan_id: Option<String>,
    pub status: JobListStatus,
    pub targets: Option<u64>,
    pub round: Option<u8>,
    pub next_index: Option<u64>,
    pub completed: Option<bool>,
    pub degraded: Option<bool>,
    pub updated_at: Option<u64>,
    pub path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct CountEntry {
    pub value: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct JobReport {
    pub status: JobStatus,
    pub protocol_counts: Vec<CountEntry>,
    pub banner_status_counts: Vec<CountEntry>,
    pub software_counts: Vec<CountEntry>,
}

#[derive(Debug, Serialize)]
pub struct JobPruneEntry {
    pub path: PathBuf,
    pub updated_at: Option<u64>,
    pub removed: bool,
}

pub fn prepare_targets(cfg: &Config) -> anyhow::Result<TargetReport> {
    let includes = target::parse_files(&cfg.targets.include)?;
    let excludes = target::parse_files(&cfg.targets.exclude)?;
    let ranges = target::filter_allowed(
        &target::subtract(&includes, &excludes),
        cfg.targets.allow_private,
    );
    Ok(TargetReport {
        include_file_count: cfg.targets.include.len(),
        exclude_file_count: cfg.targets.exclude.len(),
        target_count: target::count(&ranges).saturating_mul(cfg.scan.services().len() as u64),
    })
}

pub fn checked_target_count(cfg: &Config) -> anyhow::Result<u64> {
    let report = prepare_targets(cfg)?;
    ensure_target_count_valid(report.target_count, cfg.targets.max_targets)?;
    Ok(report.target_count)
}

pub fn validate_config(path: impl AsRef<Path>) -> anyhow::Result<ConfigValidationReport> {
    let cfg = Config::load(path)?;
    let target_report = prepare_targets(&cfg)?;
    ensure_target_count_valid(target_report.target_count, cfg.targets.max_targets)?;
    let estimate = scanner::estimate(&cfg, target_report.target_count);
    let warnings = config_warnings(&cfg, &estimate);
    Ok(ConfigValidationReport {
        target_report,
        estimate,
        job_root: cfg.output.job_root,
        allow_private: cfg.targets.allow_private,
        max_targets: cfg.targets.max_targets,
        warnings,
    })
}

fn config_warnings(cfg: &Config, estimate: &Estimate) -> Vec<String> {
    let mut warnings = Vec::new();
    if (cfg.network.tc_ratio - cfg.network.application_ratio).abs() < f64::EPSILON {
        warnings.push(
            "application_ratio equals tc_ratio; leave headroom below the hard ceiling".into(),
        );
    } else if cfg.network.tc_ratio - cfg.network.application_ratio < 0.05 {
        warnings
            .push("application_ratio is within 0.05 of tc_ratio; consider more headroom".into());
    }
    if cfg.budget.time_budget_secs.is_some() && cfg.budget.expected_open_ratio.is_none() {
        warnings.push("time_budget_secs is set but expected_open_ratio is missing; banner workload is unknown".into());
    }
    warnings.extend(estimate.budget_warnings.iter().cloned());
    warnings.sort();
    warnings.dedup();
    warnings
}

fn ensure_target_count_valid(target_count: u64, max_targets: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        target_count > 0,
        "target set is empty after exclusions and safety policy"
    );
    anyhow::ensure!(
        target_count <= max_targets,
        "target count {target_count} exceeds max_targets {max_targets}"
    );
    Ok(())
}

pub fn job_status(dir: impl AsRef<Path>) -> anyhow::Result<JobStatus> {
    let dir = dir.as_ref();
    let job = PreparedJob::open(dir).context("load job checkpoint")?;
    let cfg = Config::load(dir.join("config.toml")).context("load immutable job config")?;
    let summary = match job::load_summary(dir) {
        Ok(summary) => Some(summary),
        Err(error) if summary_missing(&error) => None,
        Err(error) => return Err(error).context("load job summary"),
    };
    build_job_status(
        dir.to_owned(),
        &job.meta,
        cfg.scan.syn_attempts,
        summary.as_ref(),
    )
}

fn build_job_status(
    job_dir: PathBuf,
    meta: &JobMeta,
    syn_attempts: u8,
    summary: Option<&ScanSummary>,
) -> anyhow::Result<JobStatus> {
    let states = match summary {
        Some(summary) => StateCounters {
            open: summary.open,
            closed: summary.closed,
            unreachable: summary.unreachable,
            no_response: summary.no_response,
        },
        None => read_state_counters(&job_dir, meta.target_count).context("read state counters")?,
    };
    let banners = match summary {
        Some(summary) => BannerCounters {
            queued: summary.banner_queued,
            done: summary.banner_done,
            failed_or_incomplete: summary.banner_failed_or_incomplete,
        },
        None => read_banner_counters(&job_dir, meta.target_count, states.open)
            .context("read banner counters")?,
    };
    let completed = summary
        .map(|summary| summary.completed)
        .unwrap_or(meta.round >= syn_attempts);
    let timed_out = summary.map(|summary| summary.timed_out).unwrap_or(false);
    let pcap_drops = summary
        .map(|summary| summary.pcap_drops)
        .unwrap_or(meta.pcap_drops)
        .max(meta.pcap_drops);
    let degraded = meta.degraded || pcap_drops > 0;
    let sent = summary
        .map(|summary| summary.sent)
        .unwrap_or(meta.packets_sent);
    let next_action = if summary.is_none() {
        NextAction::InspectMissingSummary
    } else if completed && degraded {
        NextAction::ReviewDegradedExport
    } else if completed {
        NextAction::Export
    } else {
        NextAction::Resume
    };
    let next_action = if timed_out {
        NextAction::Resume
    } else {
        next_action
    };
    Ok(JobStatus {
        scan_id: meta.scan_id.clone(),
        job_dir,
        target_count: meta.target_count,
        round: meta.round,
        syn_attempts,
        next_index: meta.next_index,
        progress_percent: progress_percent(meta, syn_attempts, completed),
        summary_present: summary.is_some(),
        completed,
        timed_out,
        degraded,
        pcap_drops,
        sent,
        states,
        banners,
        next_action,
    })
}

pub fn job_list_from_config(config: impl AsRef<Path>) -> anyhow::Result<Vec<JobListEntry>> {
    let cfg = Config::load(config)?;
    job_list(&cfg.output.job_root)
}

pub fn job_prune_from_config(
    config: impl AsRef<Path>,
    older_than_days: u64,
    dry_run: bool,
) -> anyhow::Result<Vec<JobPruneEntry>> {
    let cfg = Config::load(config)?;
    job_prune(&cfg.output.job_root, older_than_days, dry_run)
}

pub fn job_list(root: impl AsRef<Path>) -> anyhow::Result<Vec<JobListEntry>> {
    let root = root.as_ref();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !path.join("checkpoint.json").exists() {
            continue;
        }
        entries.push(job_list_entry(path));
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

pub fn job_prune(
    root: impl AsRef<Path>,
    older_than_days: u64,
    dry_run: bool,
) -> anyhow::Result<Vec<JobPruneEntry>> {
    anyhow::ensure!(older_than_days > 0, "older_than_days must be positive");
    let root = root.as_ref();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let cutoff = now.saturating_sub(older_than_days.saturating_mul(86_400));
    job_prune_before(root, cutoff, dry_run)
}

fn job_prune_before(
    root: impl AsRef<Path>,
    cutoff: u64,
    dry_run: bool,
) -> anyhow::Result<Vec<JobPruneEntry>> {
    let mut pruned = Vec::new();
    for entry in job_list(root)? {
        let Some(updated_at) = entry.updated_at else {
            continue;
        };
        if updated_at > cutoff {
            continue;
        }
        if !dry_run {
            fs::remove_dir_all(&entry.path)
                .with_context(|| format!("remove {}", entry.path.display()))?;
        }
        pruned.push(JobPruneEntry {
            path: entry.path,
            updated_at: Some(updated_at),
            removed: !dry_run,
        });
    }
    Ok(pruned)
}

pub fn job_report(dir: impl AsRef<Path>) -> anyhow::Result<JobReport> {
    let dir = dir.as_ref();
    let status = job_status(dir)?;
    let mut protocol_counts = BTreeMap::new();
    let mut banner_status_counts = BTreeMap::new();
    let mut software_counts = BTreeMap::new();
    let events = dir.join("events.ndjson");
    if events.exists() {
        for (i, line) in BufReader::new(File::open(events)?).lines().enumerate() {
            let line = line?;
            let result: crate::ResultV1 =
                serde_json::from_str(&line).with_context(|| format!("event line {}", i + 1))?;
            *protocol_counts
                .entry(json_name(result.protocol)?)
                .or_insert(0) += 1;
            if let Some(status) = result.banner_status {
                *banner_status_counts.entry(json_name(status)?).or_insert(0) += 1;
            }
            if let Some(software) = software_label(&result) {
                *software_counts.entry(software).or_insert(0) += 1;
            }
        }
    }
    Ok(JobReport {
        status,
        protocol_counts: count_entries(protocol_counts),
        banner_status_counts: count_entries(banner_status_counts),
        software_counts: count_entries(software_counts),
    })
}

fn software_label(result: &crate::ResultV1) -> Option<String> {
    if let Some(ssh) = &result.ssh {
        if let Some(version) = &ssh.software_version {
            return Some(format!("ssh:{version}"));
        }
    }
    if let Some(mysql) = &result.mysql {
        if let Some(version) = &mysql.server_version {
            return Some(format!("mysql:{version}"));
        }
    }
    if let Some(smtp) = &result.smtp {
        if let Some(domain) = &smtp.domain {
            return Some(format!("smtp:{domain}"));
        }
    }
    if let Some(redis) = &result.redis {
        if let Some(message) = &redis.message {
            return Some(format!("redis:{message}"));
        }
    }
    if let Some(postgres) = &result.postgres {
        if let Some(message_type) = &postgres.message_type {
            return Some(format!("postgres:{message_type}"));
        }
    }
    if let Some(ftp) = &result.ftp {
        if let Some(code) = ftp.code {
            return Some(format!("ftp:{code}"));
        }
    }
    result
        .banner_text
        .as_ref()
        .map(|text| format!("banner:{text}"))
}

fn json_name<T: serde::Serialize>(value: T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&value)?.trim_matches('"').to_owned())
}

fn count_entries(counts: BTreeMap<String, u64>) -> Vec<CountEntry> {
    let mut entries: Vec<_> = counts
        .into_iter()
        .map(|(value, count)| CountEntry { value, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    entries
}

fn job_list_entry(path: PathBuf) -> JobListEntry {
    let updated_at = checkpoint_updated_at(&path);
    match read_checkpoint(&path) {
        Ok(meta) => {
            let summary = match job::load_summary(&path) {
                Ok(summary) => Some(summary),
                Err(error) if summary_missing(&error) => None,
                Err(_) => {
                    return JobListEntry {
                        scan_id: Some(meta.scan_id),
                        status: JobListStatus::Invalid,
                        targets: Some(meta.target_count),
                        round: Some(meta.round),
                        next_index: Some(meta.next_index),
                        completed: None,
                        degraded: Some(meta.degraded || meta.pcap_drops > 0),
                        updated_at,
                        path,
                    };
                }
            };
            let status = list_status(&meta, summary.as_ref());
            let completed = summary
                .as_ref()
                .map(|summary| summary.completed)
                .or(Some(false));
            let degraded = Some(
                meta.degraded
                    || meta.pcap_drops > 0
                    || summary
                        .as_ref()
                        .map(|summary| summary.pcap_drops > 0)
                        .unwrap_or(false),
            );
            JobListEntry {
                scan_id: Some(meta.scan_id),
                status,
                targets: Some(meta.target_count),
                round: Some(meta.round),
                next_index: Some(meta.next_index),
                completed,
                degraded,
                updated_at,
                path,
            }
        }
        Err(_) => JobListEntry {
            scan_id: None,
            status: JobListStatus::Invalid,
            targets: None,
            round: None,
            next_index: None,
            completed: None,
            degraded: None,
            updated_at,
            path,
        },
    }
}

fn list_status(meta: &JobMeta, summary: Option<&ScanSummary>) -> JobListStatus {
    if summary.is_some_and(|summary| summary.completed) {
        JobListStatus::Completed
    } else if summary.is_some_and(|summary| summary.timed_out) {
        JobListStatus::TimedOut
    } else if meta.degraded
        || meta.pcap_drops > 0
        || summary
            .map(|summary| summary.pcap_drops > 0)
            .unwrap_or(false)
    {
        JobListStatus::Degraded
    } else if summary.is_some() {
        JobListStatus::RunningOrInterrupted
    } else {
        JobListStatus::MissingSummary
    }
}

fn read_checkpoint(dir: &Path) -> anyhow::Result<JobMeta> {
    Ok(serde_json::from_slice(&fs::read(
        dir.join("checkpoint.json"),
    )?)?)
}

fn checkpoint_updated_at(dir: &Path) -> Option<u64> {
    fs::metadata(dir.join("checkpoint.json"))
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

fn read_state_counters(dir: &Path, target_count: u64) -> anyhow::Result<StateCounters> {
    let data = read_fixed_file(dir.join("state.bin"), target_count)?;
    let mut counters = StateCounters::default();
    for value in data {
        match result::decode_state_byte(value)?.0 {
            TargetState::Open => counters.open += 1,
            TargetState::Closed => counters.closed += 1,
            TargetState::Unreachable => counters.unreachable += 1,
            TargetState::NoResponse => counters.no_response += 1,
        }
    }
    Ok(counters)
}

fn read_banner_counters(
    dir: &Path,
    target_count: u64,
    open: u64,
) -> anyhow::Result<BannerCounters> {
    let data = read_fixed_file(dir.join("banner_state.bin"), target_count)?;
    let mut counters = BannerCounters::default();
    for value in data {
        match value {
            job::BANNER_QUEUED_OR_RUNNING => counters.queued += 1,
            job::BANNER_DONE => counters.done += 1,
            _ => {}
        }
    }
    counters.failed_or_incomplete = open.saturating_sub(counters.done);
    Ok(counters)
}

fn read_fixed_file(path: PathBuf, expected_len: u64) -> anyhow::Result<Vec<u8>> {
    let data = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        data.len() as u64 == expected_len,
        "{} length {} does not match checkpoint target_count {}",
        path.display(),
        data.len(),
        expected_len
    );
    Ok(data)
}

fn progress_percent(meta: &JobMeta, syn_attempts: u8, completed: bool) -> f64 {
    if completed {
        return 100.0;
    }
    let total = meta.target_count.saturating_mul(u64::from(syn_attempts));
    if total == 0 {
        return 0.0;
    }
    let rounds_done = u64::from(meta.round).min(u64::from(syn_attempts));
    let in_round = meta.next_index.min(meta.target_count);
    let done = rounds_done
        .saturating_mul(meta.target_count)
        .saturating_add(in_round)
        .min(total);
    done as f64 * 100.0 / total as f64
}

fn summary_missing(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        NetworkConfig, OutputConfig, Protocol, ScanConfig, SourceIp, TargetsConfig,
    };
    use std::fs;

    fn config(root: &Path, include: PathBuf, max_targets: u64) -> Config {
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
                max_targets,
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
                output_all: false,
            },
            simulation: Default::default(),
        }
    }

    fn summary(completed: bool, timed_out: bool, pcap_drops: u64) -> ScanSummary {
        ScanSummary {
            completed,
            sent: 7,
            open: 1,
            closed: 1,
            unreachable: 1,
            no_response: 0,
            pcap_drops,
            banner_queued: 1,
            banner_done: 0,
            banner_failed_or_incomplete: 1,
            timed_out,
            ..Default::default()
        }
    }

    fn write_config(path: &Path, target_file: &str, max_targets: u64) -> anyhow::Result<()> {
        fs::write(
            path,
            format!(
                r#"
[scan]
port = 22
protocol = "ssh"

[targets]
include = ["{target_file}"]
max_targets = {max_targets}
allow_private = true

[network]
interface = "lo"
source_ip = "127.0.0.1"
require_tc = false

[output]
job_root = "jobs"
"#
            ),
        )?;
        Ok(())
    }

    #[test]
    fn job_status_uses_summary_when_present() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n10.0.0.3\n")?;
        let cfg = config(temp.path(), include, 10);
        let mut job = PreparedJob::create(&cfg, Some([1; 32]))?;
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;
        job::save_summary(&job.dir, &summary(true, false, 0))?;

        let status = job_status(&job.dir)?;

        assert!(status.summary_present);
        assert!(status.completed);
        assert_eq!(status.next_action, NextAction::Export);
        assert_eq!(status.progress_percent, 100.0);
        assert_eq!(status.states.open, 1);
        assert_eq!(status.banners.queued, 1);
        Ok(())
    }

    #[test]
    fn job_status_missing_summary_is_inspectable() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n10.0.0.2\n")?;
        let cfg = config(temp.path(), include, 10);
        let mut job = PreparedJob::create(&cfg, Some([2; 32]))?;
        {
            let mut states = job.states()?;
            states.copy_from_slice(&[
                result::encode_state_byte(TargetState::Open, 1),
                result::encode_state_byte(TargetState::Closed, 2),
            ]);
            states.flush()?;
            let mut banners = job.banner_states()?;
            banners.copy_from_slice(&[job::BANNER_DONE, job::BANNER_NOT_QUEUED]);
            banners.flush()?;
        }
        job.checkpoint(1)?;

        let status = job_status(&job.dir)?;

        assert!(!status.summary_present);
        assert_eq!(status.next_action, NextAction::InspectMissingSummary);
        assert_eq!(status.states.open, 1);
        assert_eq!(status.states.closed, 1);
        assert_eq!(status.banners.done, 1);
        assert!((status.progress_percent - 16.666).abs() < 0.01);
        Ok(())
    }

    #[test]
    fn job_status_degraded_and_timed_out_actions() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, 10);
        let mut job = PreparedJob::create(&cfg, Some([3; 32]))?;
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;
        job::save_summary(&job.dir, &summary(true, false, 2))?;
        assert_eq!(
            job_status(&job.dir)?.next_action,
            NextAction::ReviewDegradedExport
        );

        job::save_summary(&job.dir, &summary(false, true, 0))?;
        assert_eq!(job_status(&job.dir)?.next_action, NextAction::Resume);
        Ok(())
    }

    #[test]
    fn job_list_handles_empty_root_and_invalid_job() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        assert!(job_list(temp.path().join("missing"))?.is_empty());

        let invalid = temp.path().join("bad");
        fs::create_dir_all(&invalid)?;
        fs::write(invalid.join("checkpoint.json"), b"not json")?;
        let entries = job_list(temp.path())?;

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, JobListStatus::Invalid);
        Ok(())
    }

    #[test]
    fn job_list_reports_multiple_valid_jobs() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, 10);
        let job_a = PreparedJob::create(&cfg, Some([4; 32]))?;
        job::save_summary(&job_a.dir, &summary(false, true, 0))?;
        let mut job_b = PreparedJob::create(&cfg, Some([5; 32]))?;
        job_b.meta.degraded = true;
        job_b.checkpoint(0)?;

        let entries = job_list(temp.path())?;

        assert_eq!(entries.len(), 2);
        assert!(
            entries
                .iter()
                .any(|entry| entry.status == JobListStatus::TimedOut)
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.status == JobListStatus::Degraded)
        );
        Ok(())
    }

    #[test]
    fn validate_config_reports_valid_inputs() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n10.0.0.2\n")?;
        let config_path = temp.path().join("config.toml");
        write_config(&config_path, "targets.txt", 10)?;

        let report = validate_config(&config_path)?;

        assert_eq!(report.target_report.include_file_count, 1);
        assert_eq!(report.target_report.target_count, 2);
        assert_eq!(report.estimate.targets, 2);
        assert_eq!(report.job_root, temp.path().join("jobs"));
        Ok(())
    }

    #[test]
    fn validate_config_counts_multiple_service_endpoints() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n10.0.0.2\n")?;
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
[scan]
port = 22
protocol = "ssh"
services = [
  { port = 22, protocol = "ssh" },
  { port = 25, protocol = "smtp" },
]

[targets]
include = ["targets.txt"]
max_targets = 10
allow_private = true

[network]
interface = "lo"
source_ip = "127.0.0.1"
require_tc = false

[output]
job_root = "jobs"
"#,
        )?;

        let report = validate_config(&config_path)?;

        assert_eq!(report.target_report.target_count, 4);
        assert_eq!(report.estimate.targets, 4);
        Ok(())
    }

    #[test]
    fn validate_config_rejects_duplicate_service_ports() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n")?;
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
[scan]
port = 22
protocol = "ssh"
services = [
  { port = 22, protocol = "ssh" },
  { port = 22, protocol = "smtp" },
]

[targets]
include = ["targets.txt"]
max_targets = 10
allow_private = true

[network]
interface = "lo"
source_ip = "127.0.0.1"
require_tc = false

[output]
job_root = "jobs"
"#,
        )?;

        assert!(
            validate_config(&config_path)
                .unwrap_err()
                .to_string()
                .contains("duplicate scan service port 22")
        );
        Ok(())
    }

    #[test]
    fn validate_config_reports_lint_warnings() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n")?;
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            r#"
[scan]
port = 22
protocol = "ssh"

[budget]
time_budget_secs = 7200

[targets]
include = ["targets.txt"]
max_targets = 10
allow_private = true

[network]
interface = "lo"
source_ip = "127.0.0.1"
application_ratio = 0.85
tc_ratio = 0.85
require_tc = false

[output]
job_root = "jobs"
"#,
        )?;

        let report = validate_config(&config_path)?;

        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("application_ratio equals tc_ratio"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("expected_open_ratio"))
        );
        Ok(())
    }

    #[test]
    fn job_report_summarizes_events() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, 10);
        let mut job = PreparedJob::create(&cfg, Some([6; 32]))?;
        job.meta.round = cfg.scan.syn_attempts;
        job.checkpoint(job.meta.target_count)?;
        job::save_summary(&job.dir, &summary(true, false, 0))?;
        let ip = "10.0.0.1".parse()?;
        job::append_event(
            &job.dir,
            &crate::ResultV1 {
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
                ssh: Some(crate::result::SshFields {
                    protocol_version: Some("2.0".into()),
                    software_version: Some("OpenSSH_9.6".into()),
                    comments: None,
                    ..Default::default()
                }),
                ftp: None,
                mysql: None,
                smtp: None,
                redis: None,
                postgres: None,
            },
        )?;

        let report = job_report(&job.dir)?;

        assert_eq!(report.protocol_counts[0].value, "ssh");
        assert_eq!(report.banner_status_counts[0].value, "ok");
        assert_eq!(report.software_counts[0].value, "ssh:OpenSSH_9.6");
        assert!(report.status.completed);
        Ok(())
    }

    #[test]
    fn job_prune_removes_only_checkpoint_jobs_before_cutoff() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let include = temp.path().join("targets.txt");
        fs::write(&include, "10.0.0.1\n")?;
        let cfg = config(temp.path(), include, 10);
        let job = PreparedJob::create(&cfg, Some([7; 32]))?;
        let keep = temp.path().join("not-a-job");
        fs::create_dir_all(&keep)?;

        let dry_run = job_prune_before(temp.path(), u64::MAX, true)?;
        assert_eq!(dry_run.len(), 1);
        assert!(!dry_run[0].removed);
        assert!(job.dir.exists());

        let removed = job_prune_before(temp.path(), u64::MAX, false)?;

        assert_eq!(removed.len(), 1);
        assert!(removed[0].removed);
        assert!(!job.dir.exists());
        assert!(keep.exists());
        Ok(())
    }

    #[test]
    fn validate_config_rejects_empty_and_over_max_targets() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n")?;
        let config_path = temp.path().join("config.toml");
        write_config(&config_path, "targets.txt", 0)?;
        assert!(
            validate_config(&config_path)
                .unwrap_err()
                .to_string()
                .contains("max_targets must be positive")
        );

        write_config(&config_path, "targets.txt", 1)?;
        fs::write(temp.path().join("targets.txt"), "10.0.0.1\n10.0.0.2\n")?;
        assert!(
            validate_config(&config_path)
                .unwrap_err()
                .to_string()
                .contains("exceeds max_targets")
        );

        fs::write(temp.path().join("targets.txt"), "127.0.0.1\n")?;
        assert!(
            validate_config(&config_path)
                .unwrap_err()
                .to_string()
                .contains("target set is empty")
        );
        Ok(())
    }

    #[test]
    fn validate_config_rejects_missing_target_file() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let config_path = temp.path().join("config.toml");
        write_config(&config_path, "missing.txt", 10)?;

        assert!(
            validate_config(&config_path)
                .unwrap_err()
                .to_string()
                .contains("missing.txt")
        );
        Ok(())
    }
}
