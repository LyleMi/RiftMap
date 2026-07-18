use anyhow::Context;
use clap::{Parser, Subcommand};
use riftmap::{
    Config,
    job::PreparedJob,
    ops::{ConfigValidationReport, JobListEntry, JobStatus},
};
use std::path::{Path, PathBuf};

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
    },
    Resume {
        #[arg(long)]
        job: PathBuf,
    },
    Export {
        #[arg(long)]
        job: PathBuf,
    },
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
}

#[derive(Subcommand)]
enum JobCommand {
    Status {
        #[arg(long)]
        job: PathBuf,
    },
    List {
        #[arg(short = 'c', long)]
        config: PathBuf,
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
}

fn print_job_status(status: &JobStatus) {
    println!("scan_id: {}", status.scan_id);
    println!("job_dir: {}", status.job_dir.display());
    println!("target_count: {}", status.target_count);
    println!("round: {}", status.round);
    println!("syn_attempts: {}", status.syn_attempts);
    println!("next_index: {}", status.next_index);
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
        Command::Scan { config, dry_run } => {
            let c = Config::load(config)?;
            let mut j = PreparedJob::create(&c, None)?;
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
        Command::Export { job } => {
            let c = load_job_cfg(&job)?;
            println!(
                "exported: {}",
                riftmap::job::export(&job, c.output.output_all)?
            );
        }
        Command::Job { command } => match command {
            JobCommand::Status { job } => {
                print_job_status(&riftmap::ops::job_status(job)?);
            }
            JobCommand::List { config } => {
                print_job_list(&riftmap::ops::job_list_from_config(config)?);
            }
        },
    }
    Ok(())
}
