use anyhow::Context;
use clap::{Parser, Subcommand};
use riftmap::{Config, job::PreparedJob};
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
}
fn prepare_count(cfg: &Config) -> anyhow::Result<u64> {
    let i = riftmap::target::parse_files(&cfg.targets.include)?;
    let e = riftmap::target::parse_files(&cfg.targets.exclude)?;
    let r = riftmap::target::filter_allowed(
        &riftmap::target::subtract(&i, &e),
        cfg.targets.allow_private,
    );
    let n = riftmap::target::count(&r);
    anyhow::ensure!(
        n <= cfg.targets.max_targets,
        "target count {n} exceeds max_targets {}",
        cfg.targets.max_targets
    );
    Ok(n)
}
fn load_job_cfg(dir: &Path) -> anyhow::Result<Config> {
    Config::load(dir.join("config.toml"))
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
            let e = riftmap::scanner::estimate(&c, prepare_count(&c)?);
            println!(
                "targets: {}\nworst_packets: {}\nestimated_wire_bytes: {}\nsyn_seconds: {:.1}\nbanner_capacity_cps: {:.1}",
                e.targets,
                e.worst_packets,
                e.estimated_wire_bytes,
                e.syn_seconds,
                e.banner_capacity_cps
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
            for warning in e.budget_warnings {
                println!("budget_warning: {warning}");
            }
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
    }
    Ok(())
}
