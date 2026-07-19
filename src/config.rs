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
pub(crate) fn d_sim_seed() -> String {
    "riftmap-sim-v1".into()
}
pub(crate) fn d_sim_open_ratio() -> f64 {
    0.01
}
pub(crate) fn d_sim_closed_ratio() -> f64 {
    0.10
}
pub(crate) fn d_sim_unreachable_ratio() -> f64 {
    0.01
}
pub(crate) fn d_sim_rtt_min_ms() -> f64 {
    1.0
}
pub(crate) fn d_sim_rtt_max_ms() -> f64 {
    200.0
}
pub(crate) fn d_ssh_client_id() -> String {
    "SSH-2.0-RiftMap_0.1".into()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Ftp,
    Mysql,
    Smtp,
    Redis,
    Postgres,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceConfig {
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshProbeMode {
    #[default]
    PassiveBanner,
    VersionExchange,
    KexinitProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    #[serde(default)]
    pub probe_mode: SshProbeMode,
    #[serde(default = "d_ssh_client_id")]
    pub client_id: String,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            probe_mode: SshProbeMode::PassiveBanner,
            client_id: d_ssh_client_id(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
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
    #[serde(default)]
    pub ssh: SshConfig,
}

impl ScanConfig {
    pub fn services(&self) -> Vec<ServiceConfig> {
        if self.services.is_empty() {
            vec![ServiceConfig {
                port: self.port,
                protocol: self.protocol,
            }]
        } else {
            self.services.clone()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default)]
    pub time_budget_secs: Option<u64>,
    #[serde(default)]
    pub expected_open_ratio: Option<f64>,
    #[serde(default)]
    pub enforce_time_budget: bool,
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
    #[serde(default)]
    pub dynamic_application_mbps_file: Option<PathBuf>,
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
pub struct SimulationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "d_sim_open_ratio")]
    pub open_ratio: f64,
    #[serde(default = "d_sim_closed_ratio")]
    pub closed_ratio: f64,
    #[serde(default = "d_sim_unreachable_ratio")]
    pub unreachable_ratio: f64,
    #[serde(default = "d_sim_seed")]
    pub seed: String,
    #[serde(default = "d_sim_rtt_min_ms")]
    pub rtt_min_ms: f64,
    #[serde(default = "d_sim_rtt_max_ms")]
    pub rtt_max_ms: f64,
    #[serde(default = "d_true")]
    pub banner: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            open_ratio: d_sim_open_ratio(),
            closed_ratio: d_sim_closed_ratio(),
            unreachable_ratio: d_sim_unreachable_ratio(),
            seed: d_sim_seed(),
            rtt_min_ms: d_sim_rtt_min_ms(),
            rtt_max_ms: d_sim_rtt_max_ms(),
            banner: true,
        }
    }
}

fn d_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan: ScanConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    pub targets: TargetsConfig,
    pub network: NetworkConfig,
    pub output: OutputConfig,
    #[serde(default)]
    pub simulation: SimulationConfig,
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
        if let Some(path) = &mut cfg.network.dynamic_application_mbps_file {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        cfg.validate()?;
        // Avoid retaining toml internals containing accidental future secrets.
        value = toml::Value::Table(Default::default());
        drop(value);
        Ok(cfg)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.scan.source_port != 0, "source_port must be non-zero");
        let services = self.scan.services();
        anyhow::ensure!(
            !services.is_empty(),
            "at least one scan service is required"
        );
        let mut ports = std::collections::BTreeSet::new();
        for service in &services {
            anyhow::ensure!(service.port != 0, "scan service ports must be non-zero");
            anyhow::ensure!(
                ports.insert(service.port),
                "duplicate scan service port {}",
                service.port
            );
        }
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
        anyhow::ensure!(
            self.scan.ssh.client_id.starts_with("SSH-2.0-")
                && self.scan.ssh.client_id.is_ascii()
                && !self.scan.ssh.client_id.contains(['\r', '\n'])
                && self.scan.ssh.client_id.len() <= 253,
            "scan.ssh.client_id must be an ASCII SSH-2.0 identification string without CR/LF"
        );
        anyhow::ensure!(self.targets.max_targets > 0, "max_targets must be positive");
        anyhow::ensure!(
            self.network.provider_egress_mbps > 0.0,
            "provider egress must be positive"
        );
        anyhow::ensure!(
            (0.0..=1.0).contains(&self.network.application_ratio),
            "application_ratio must be in 0..=1"
        );
        if let Some(path) = &self.network.dynamic_application_mbps_file {
            anyhow::ensure!(
                !path.as_os_str().is_empty(),
                "dynamic_application_mbps_file must not be empty"
            );
        }
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
        anyhow::ensure!(
            !self.budget.enforce_time_budget || self.budget.time_budget_secs.is_some(),
            "enforce_time_budget requires time_budget_secs"
        );
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
        for (name, ratio) in [
            ("simulation.open_ratio", self.simulation.open_ratio),
            ("simulation.closed_ratio", self.simulation.closed_ratio),
            (
                "simulation.unreachable_ratio",
                self.simulation.unreachable_ratio,
            ),
        ] {
            anyhow::ensure!((0.0..=1.0).contains(&ratio), "{name} must be in 0..=1");
        }
        anyhow::ensure!(
            self.simulation.open_ratio
                + self.simulation.closed_ratio
                + self.simulation.unreachable_ratio
                <= 1.0,
            "simulation state ratios must not exceed 1.0 in total"
        );
        anyhow::ensure!(
            self.simulation.rtt_min_ms.is_finite()
                && self.simulation.rtt_max_ms.is_finite()
                && self.simulation.rtt_min_ms >= 0.0
                && self.simulation.rtt_max_ms >= self.simulation.rtt_min_ms,
            "simulation RTT range is invalid"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_simulation(simulation: SimulationConfig) -> Config {
        Config {
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
                banner_concurrency: 8,
                banner_connects_per_second: 10,
                banner_queue_capacity: 128,
                max_runtime_secs: None,
                ssh: Default::default(),
            },
            budget: BudgetConfig::default(),
            targets: TargetsConfig {
                include: vec![PathBuf::from("targets.txt")],
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
                job_root: PathBuf::from("."),
                output_all: false,
            },
            simulation,
        }
    }

    #[test]
    fn simulation_defaults_are_valid() -> anyhow::Result<()> {
        config_with_simulation(SimulationConfig::default()).validate()
    }

    #[test]
    fn simulation_ratios_must_not_exceed_one() {
        let cfg = config_with_simulation(SimulationConfig {
            enabled: true,
            open_ratio: 0.6,
            closed_ratio: 0.3,
            unreachable_ratio: 0.2,
            ..Default::default()
        });

        assert!(
            cfg.validate()
                .unwrap_err()
                .to_string()
                .contains("must not exceed 1.0")
        );
    }
}
