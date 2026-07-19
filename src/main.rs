use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use riftmap::{
    BannerStatus, Config, Protocol, TargetState,
    job::PreparedJob,
    ops::{ConfigValidationReport, JobListEntry, JobStatus},
};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Doctor {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    Estimate {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    ValidateConfig {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    TcTemplate {
        #[arg(short = 'c', long)]
        config: PathBuf,
    },
    Scan {
        #[arg(short = 'c', long)]
        config: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = 0)]
        shard_index: u32,
        #[arg(long, default_value_t = 1)]
        shard_count: u32,
    },
    Resume {
        #[arg(long)]
        job: PathBuf,
    },
    Export {
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        state: Option<CliTargetState>,
        #[arg(long)]
        protocol: Option<CliProtocol>,
        #[arg(long)]
        banner_status: Option<CliBannerStatus>,
        #[arg(long, value_enum, default_value_t = CliExportFormat::Ndjson)]
        format: CliExportFormat,
    },
    Report {
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        json: bool,
    },
    ValidationReport {
        #[arg(short = 'c', long)]
        config: PathBuf,
        #[arg(long)]
        job: PathBuf,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliExportFormat {
    Ndjson,
    Csv,
}

impl From<CliExportFormat> for riftmap::job::ExportFormat {
    fn from(value: CliExportFormat) -> Self {
        match value {
            CliExportFormat::Ndjson => Self::Ndjson,
            CliExportFormat::Csv => Self::Csv,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliTargetState {
    NoResponse,
    Unreachable,
    Closed,
    Open,
}

impl From<CliTargetState> for TargetState {
    fn from(value: CliTargetState) -> Self {
        match value {
            CliTargetState::NoResponse => Self::NoResponse,
            CliTargetState::Unreachable => Self::Unreachable,
            CliTargetState::Closed => Self::Closed,
            CliTargetState::Open => Self::Open,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliProtocol {
    Ssh,
    Ftp,
    Mysql,
    Smtp,
    Redis,
    Postgres,
}

impl From<CliProtocol> for Protocol {
    fn from(value: CliProtocol) -> Self {
        match value {
            CliProtocol::Ssh => Self::Ssh,
            CliProtocol::Ftp => Self::Ftp,
            CliProtocol::Mysql => Self::Mysql,
            CliProtocol::Smtp => Self::Smtp,
            CliProtocol::Redis => Self::Redis,
            CliProtocol::Postgres => Self::Postgres,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CliBannerStatus {
    Ok,
    ConnectFailed,
    Timeout,
    ProtocolMismatch,
    Oversized,
}

impl From<CliBannerStatus> for BannerStatus {
    fn from(value: CliBannerStatus) -> Self {
        match value {
            CliBannerStatus::Ok => Self::Ok,
            CliBannerStatus::ConnectFailed => Self::ConnectFailed,
            CliBannerStatus::Timeout => Self::Timeout,
            CliBannerStatus::ProtocolMismatch => Self::ProtocolMismatch,
            CliBannerStatus::Oversized => Self::Oversized,
        }
    }
}

#[derive(Subcommand)]
enum JobCommand {
    Status {
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(short = 'c', long)]
        config: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Prune {
        #[arg(short = 'c', long)]
        config: PathBuf,
        #[arg(long)]
        older_than_days: u64,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
}

fn load_job_cfg(dir: &Path) -> anyhow::Result<Config> {
    Config::load(dir.join("config.toml"))
}

fn print_estimate(e: &riftmap::scanner::Estimate) {
    println!(
        "targets: {}\nworst_packets: {}\nestimated_wire_bytes: {}\nsyn_seconds: {:.1}\nbanner_capacity_cps: {:.1}",
        e.targets, e.worst_packets, e.estimated_wire_bytes, e.syn_seconds, e.banner_capacity_cps
    );
    if let Some(mbps) = e.required_syn_application_mbps {
        println!("required_syn_application_mbps: {mbps:.3}");
    }
    if let Some(mbps) = e.recommended_provider_egress_mbps {
        println!("recommended_provider_egress_mbps: {mbps:.3}");
    }
    if let Some(open) = e.expected_open {
        println!("expected_open_targets: {open:.0}");
    }
    if let Some(open) = e.banner_budget_capacity_open {
        println!("banner_budget_capacity_open: {open:.0}");
    }
    if let Some(seconds) = e.banner_seconds {
        println!("banner_seconds: {seconds:.1}");
    }
    if let Some(seconds) = e.estimated_total_seconds {
        println!("estimated_total_seconds: {seconds:.1}");
    }
    for warning in &e.budget_warnings {
        println!("budget_warning: {warning}");
    }
}

fn print_config_validation(report: &ConfigValidationReport) {
    println!("config: ok");
    println!("include_files: {}", report.target_report.include_file_count);
    println!("exclude_files: {}", report.target_report.exclude_file_count);
    println!("target_count: {}", report.target_report.target_count);
    println!(
        "max_targets: {} ({})",
        report.max_targets,
        if report.target_report.target_count <= report.max_targets {
            "ok"
        } else {
            "exceeded"
        }
    );
    println!("job_root: {}", report.job_root.display());
    println!("allow_private: {}", report.allow_private);
    print_estimate(&report.estimate);
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

fn print_job_status(status: &JobStatus) {
    println!("scan_id: {}", status.scan_id);
    println!("job_dir: {}", status.job_dir.display());
    println!("target_count: {}", status.target_count);
    println!("round: {}", status.round);
    println!("syn_attempts: {}", status.syn_attempts);
    println!("next_index: {}", status.next_index);
    println!(
        "progress: {}",
        riftmap::scanner::human_progress(
            status.target_count,
            status.syn_attempts,
            status.round,
            status.next_index,
            status.completed,
        )
    );
    println!("progress_percent: {:.2}", status.progress_percent);
    println!(
        "summary: {}",
        if status.summary_present {
            "present"
        } else {
            "missing"
        }
    );
    println!("completed: {}", status.completed);
    println!("timed_out: {}", status.timed_out);
    println!("degraded: {}", status.degraded);
    println!("pcap_drops: {}", status.pcap_drops);
    println!("sent: {}", status.sent);
    println!("state_open: {}", status.states.open);
    println!("state_closed: {}", status.states.closed);
    println!("state_unreachable: {}", status.states.unreachable);
    println!("state_no_response: {}", status.states.no_response);
    println!("banner_queued: {}", status.banners.queued);
    println!("banner_done: {}", status.banners.done);
    println!(
        "banner_failed_or_incomplete: {}",
        status.banners.failed_or_incomplete
    );
    println!("next_action: {}", status.next_action.as_str());
}

fn print_job_list(entries: &[JobListEntry]) {
    for entry in entries {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            optional_string(entry.scan_id.as_deref()),
            entry.status.as_str(),
            optional_display(entry.targets),
            optional_display(entry.round),
            optional_display(entry.next_index),
            optional_display(entry.completed),
            optional_display(entry.degraded),
            optional_display(entry.updated_at),
            entry.path.display()
        );
    }
}

fn print_prune(entries: &[riftmap::ops::JobPruneEntry]) {
    for entry in entries {
        println!(
            "{}\t{}\t{}",
            if entry.removed {
                "removed"
            } else {
                "would_remove"
            },
            optional_display(entry.updated_at),
            entry.path.display()
        );
    }
}

fn print_report(report: &riftmap::ops::JobReport) {
    print_job_status(&report.status);
    print_count_section("protocol", &report.protocol_counts);
    print_count_section("banner_status", &report.banner_status_counts);
    print_count_section("software", &report.software_counts);
}

fn print_count_section(name: &str, entries: &[riftmap::ops::CountEntry]) {
    for entry in entries {
        println!("{name}: {}\t{}", entry.value, entry.count);
    }
}

fn validation_report(config: &Path, job: &Path) -> anyhow::Result<serde_json::Value> {
    let cfg = Config::load(config)?;
    let target_count = riftmap::ops::checked_target_count(&cfg)?;
    let estimate = riftmap::scanner::estimate(&cfg, target_count);
    let status = riftmap::ops::job_status(job)?;
    let report = riftmap::ops::job_report(job)?;
    let summary = riftmap::job::load_summary(job).ok();
    Ok(json!({
        "schema_version": 1,
        "host": host_report(),
        "network": {
            "interface": cfg.network.interface,
            "source_ip": cfg.network.source_ip.0,
            "provider_egress_mbps": cfg.network.provider_egress_mbps,
            "application_ratio": cfg.network.application_ratio,
            "tc_ratio": cfg.network.tc_ratio,
            "require_tc": cfg.network.require_tc,
            "tc_qdisc": command_json("tc", &["-s", "-j", "qdisc", "show", "dev", &cfg.network.interface]),
        },
        "scan": {
            "services": cfg.scan.services(),
            "syn_attempts": cfg.scan.syn_attempts,
            "source_port": cfg.scan.source_port,
            "connect_timeout_ms": cfg.scan.connect_timeout_ms,
            "banner_timeout_ms": cfg.scan.banner_timeout_ms,
            "banner_concurrency": cfg.scan.banner_concurrency,
            "banner_connects_per_second": cfg.scan.banner_connects_per_second,
            "max_runtime_secs": cfg.scan.max_runtime_secs,
        },
        "targets": {
            "endpoint_count": target_count,
            "max_targets": cfg.targets.max_targets,
            "allow_private": cfg.targets.allow_private,
        },
        "budget": {
            "time_budget_secs": cfg.budget.time_budget_secs,
            "expected_open_ratio": cfg.budget.expected_open_ratio,
            "enforce_time_budget": cfg.budget.enforce_time_budget,
        },
        "estimate": estimate,
        "job": {
            "path": job,
            "size_bytes": dir_size(job).unwrap_or(0),
            "status": status,
            "summary": summary,
            "report": report,
        }
    }))
}

fn host_report() -> serde_json::Value {
    json!({
        "kernel": command_stdout("uname", &["-a"]),
        "cpu": fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("model name\t: "))
                .map(str::to_owned)
        }),
        "memory_kb": fs::read_to_string("/proc/meminfo").ok().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("MemTotal:"))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        }),
        "libpcap": command_stdout("pkg-config", &["--modversion", "libpcap"]),
    })
}

fn command_json(command: &str, args: &[&str]) -> serde_json::Value {
    match ProcessCommand::new(command).args(args).output() {
        Ok(output) => json!({
            "status": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({ "error": error.to_string() }),
    }
}

fn command_stdout(command: &str, args: &[&str]) -> Option<String> {
    ProcessCommand::new(command)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn dir_size(path: &Path) -> anyhow::Result<u64> {
    let mut size = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            size = size.saturating_add(dir_size(&entry.path())?);
        } else {
            size = size.saturating_add(metadata.len());
        }
    }
    Ok(size)
}

fn optional_string(value: Option<&str>) -> &str {
    value.unwrap_or("unknown")
}

fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        Command::Doctor { config } => {
            let c = Config::load(config)?;
            for x in riftmap::scanner::doctor(&c)? {
                println!("ok: {x}");
            }
        }
        Command::Estimate { config } => {
            let c = Config::load(config)?;
            let e = riftmap::scanner::estimate(&c, riftmap::ops::checked_target_count(&c)?);
            print_estimate(&e);
        }
        Command::ValidateConfig { config } => {
            print_config_validation(&riftmap::ops::validate_config(config)?);
        }
        Command::TcTemplate { config } => {
            let c = Config::load(config)?;
            print!("{}", riftmap::scanner::tc_template(&c));
        }
        Command::Scan {
            config,
            dry_run,
            shard_index,
            shard_count,
        } => {
            let c = Config::load(config)?;
            let mut j = PreparedJob::create_shard(&c, None, shard_index, shard_count)?;
            println!("job: {}", j.dir.display());
            if dry_run {
                println!("order_digest: {}", riftmap::scanner::dry_run(&j)?);
            } else {
                println!("summary: {:?}", riftmap::scanner::scan(&mut j, &c)?);
            }
        }
        Command::Resume { job } => {
            let c = load_job_cfg(&job).context("load immutable job config")?;
            let mut j = PreparedJob::open(job)?;
            println!("summary: {:?}", riftmap::scanner::scan(&mut j, &c)?);
        }
        Command::Export {
            job,
            state,
            protocol,
            banner_status,
            format,
        } => {
            let c = load_job_cfg(&job)?;
            let format = riftmap::job::ExportFormat::from(format);
            let output_name = match format {
                riftmap::job::ExportFormat::Ndjson => "results.ndjson",
                riftmap::job::ExportFormat::Csv => "results.csv",
            };
            let options = riftmap::job::ExportOptions {
                output_all: c.output.output_all,
                state: state.map(Into::into),
                protocol: protocol.map(Into::into),
                banner_status: banner_status.map(Into::into),
            };
            println!(
                "exported: {}\noutput: {}",
                riftmap::job::export_with_options(&job, &options, format)?,
                job.join(output_name).display()
            );
        }
        Command::Report { job, json } => {
            let report = riftmap::ops::job_report(job)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }
        }
        Command::ValidationReport { config, job } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&validation_report(&config, &job)?)?
            );
        }
        Command::Job { command } => match command {
            JobCommand::Status { job, json } => {
                let status = riftmap::ops::job_status(job)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    print_job_status(&status);
                }
            }
            JobCommand::List { config, json } => {
                let entries = riftmap::ops::job_list_from_config(config)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    print_job_list(&entries);
                }
            }
            JobCommand::Prune {
                config,
                older_than_days,
                dry_run,
                json,
            } => {
                let entries =
                    riftmap::ops::job_prune_from_config(config, older_than_days, dry_run)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&entries)?);
                } else {
                    print_prune(&entries);
                }
            }
        },
    }
    Ok(())
}
