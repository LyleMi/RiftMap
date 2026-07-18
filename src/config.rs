use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

pub(crate) fn d_syn_attempts() -> u8 {
    3
}
pub(crate) fn d_source_port() -> u16 {
    61000
}
pub(crate) fn d_connect_timeout() -> u64 {
    3000
}
pub(crate) fn d_banner_timeout() -> u64 {
    5000
}
pub(crate) fn d_banner_bytes() -> usize {
    4096
}
pub(crate) fn d_banner_attempts() -> u8 {
    2
}
pub(crate) fn d_concurrency() -> usize {
    512
}
pub(crate) fn d_cps() -> u32 {
    200
}
pub(crate) fn d_banner_queue_capacity() -> usize {
    8192
}
pub(crate) fn d_max_targets() -> u64 {
    25_000_000
}
pub(crate) fn d_provider() -> f64 {
    100.0
}
pub(crate) fn d_app_ratio() -> f64 {
    0.80
}
pub(crate) fn d_tc_ratio() -> f64 {
    0.85
}
pub(crate) fn d_require_tc() -> bool {
    true
}
pub(crate) fn d_accounting() -> String {
    "estimated-wire".into()
}
pub(crate) fn d_job_root() -> PathBuf {
    ".riftmap/jobs".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Ftp,
    Mysql,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default = "d_syn_attempts")]
    pub syn_attempts: u8,
    #[serde(default = "d_source_port")]
    pub source_port: u16,
    #[serde(default = "d_connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "d_banner_timeout")]
    pub banner_timeout_ms: u64,
    #[serde(default = "d_banner_bytes")]
    pub banner_max_bytes: usize,
    #[serde(default = "d_banner_attempts")]
    pub banner_attempts: u8,
    #[serde(default = "d_concurrency")]
    pub banner_concurrency: usize,
    #[serde(default = "d_cps")]
    pub banner_connects_per_second: u32,
    #[serde(default = "d_banner_queue_capacity")]
    pub banner_queue_capacity: usize,
    #[serde(default)]
    pub max_runtime_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default)]
    pub time_budget_secs: Option<u64>,
    #[serde(default)]
    pub expected_open_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetsConfig {
    pub include: Vec<PathBuf>,
    #[serde(default)]
    pub exclude: Vec<PathBuf>,
    #[serde(default)]
    pub allow_private: bool,
    #[serde(default = "d_max_targets")]
    pub max_targets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceIp(pub String);
impl SourceIp {
    pub fn is_auto(&self) -> bool {
        self.0 == "auto"
    }
    pub fn address(&self) -> Option<Ipv4Addr> {
        if self.is_auto() {
            None
        } else {
            self.0.parse().ok()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub source_ip: SourceIp,
    #[serde(default = "d_provider")]
    pub provider_egress_mbps: f64,
    #[serde(default = "d_app_ratio")]
    pub application_ratio: f64,
    #[serde(default = "d_tc_ratio")]
    pub tc_ratio: f64,
    #[serde(default = "d_require_tc")]
    pub require_tc: bool,
    #[serde(default = "d_accounting")]
    pub accounting: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "d_job_root")]
    pub job_root: PathBuf,
    #[serde(default)]
    pub output_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    pub targets: TargetsConfig,
    pub network: NetworkConfig,
    pub output: OutputConfig,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let mut value: toml::Value = toml::from_str(&fs::read_to_string(path)?)?;
        let base = path.parent().unwrap_or(Path::new("."));
        let mut cfg: Self = value.clone().try_into()?;
        for p in cfg
            .targets
            .include
            .iter_mut()
            .chain(cfg.targets.exclude.iter_mut())
        {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        if cfg.output.job_root.is_relative() {
            cfg.output.job_root = base.join(&cfg.output.job_root);
        }
        cfg.validate()?;
        // Avoid retaining toml internals containing accidental future secrets.
        value = toml::Value::Table(Default::default());
        drop(value);
        Ok(cfg)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.scan.port != 0 && self.scan.source_port != 0,
            "ports must be non-zero"
        );
        anyhow::ensure!(
            (1..=3).contains(&self.scan.syn_attempts),
            "syn_attempts must be 1..=3"
        );
        anyhow::ensure!(
            self.scan.banner_max_bytes > 0 && self.scan.banner_max_bytes <= 1_048_576,
            "invalid banner_max_bytes"
        );
        anyhow::ensure!(
            self.scan.banner_concurrency > 0,
            "banner_concurrency must be positive"
        );
        anyhow::ensure!(
            self.scan.banner_connects_per_second > 0,
            "banner_connects_per_second must be positive"
        );
        anyhow::ensure!(
            self.scan.banner_queue_capacity > 0,
            "banner_queue_capacity must be positive"
        );
        if let Some(max_runtime_secs) = self.scan.max_runtime_secs {
            anyhow::ensure!(max_runtime_secs > 0, "max_runtime_secs must be positive");
        }
        anyhow::ensure!(self.targets.max_targets > 0, "max_targets must be positive");
        anyhow::ensure!(
            self.network.provider_egress_mbps > 0.0,
            "provider egress must be positive"
        );
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.network.application_ratio),
            "application_ratio must be in 0..=1"
        );
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.network.tc_ratio),
            "tc_ratio must be in 0..=1"
        );
        anyhow::ensure!(
            self.network.application_ratio <= self.network.tc_ratio,
            "application_ratio must not exceed tc_ratio"
        );
        anyhow::ensure!(
            self.network.accounting == "estimated-wire",
            "only estimated-wire accounting is supported"
        );
        if let Some(time_budget_secs) = self.budget.time_budget_secs {
            anyhow::ensure!(time_budget_secs > 0, "time_budget_secs must be positive");
        }
        if let Some(expected_open_ratio) = self.budget.expected_open_ratio {
            anyhow::ensure!(
                (0.0..=1.0).contains(&expected_open_ratio),
                "expected_open_ratio must be in 0..=1"
            );
        }
        anyhow::ensure!(
            self.network.source_ip.is_auto() || self.network.source_ip.address().is_some(),
            "source_ip must be auto or IPv4"
        );
        Ok(())
    }
}
