use crate::Protocol;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    NoResponse,
    Unreachable,
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BannerStatus {
    Ok,
    ConnectFailed,
    Timeout,
    ProtocolMismatch,
    Oversized,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshFields {
    pub protocol_version: Option<String>,
    pub software_version: Option<String>,
    pub comments: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FtpFields {
    pub code: Option<u16>,
    pub multiline: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MysqlFields {
    pub protocol_version: Option<u8>,
    pub server_version: Option<String>,
    pub connection_id: Option<u32>,
    pub capabilities: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultV1 {
    pub schema_version: u32,
    pub result_id: String,
    pub scan_id: String,
    pub ip: std::net::Ipv4Addr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: TargetState,
    pub syn_attempts: u8,
    pub rtt_ms: Option<f64>,
    pub first_observed_at: Option<String>,
    pub last_observed_at: Option<String>,
    pub banner_status: Option<BannerStatus>,
    pub banner_base64: Option<String>,
    pub banner_text: Option<String>,
    pub ssh: Option<SshFields>,
    pub ftp: Option<FtpFields>,
    pub mysql: Option<MysqlFields>,
}

pub fn result_id(scan_id: &str, ip: std::net::Ipv4Addr, port: u16) -> String {
    let mut h = blake3::Hasher::new();
    h.update(scan_id.as_bytes());
    h.update(&ip.octets());
    h.update(&port.to_be_bytes());
    h.finalize().to_hex().to_string()
}
