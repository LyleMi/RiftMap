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

impl TargetState {
    pub(crate) fn rank(self) -> u8 {
        match self {
            TargetState::NoResponse => 0,
            TargetState::Unreachable => 1,
            TargetState::Closed => 2,
            TargetState::Open => 3,
        }
    }
}

pub(crate) fn encode_state_byte(state: TargetState, syn_attempts: u8) -> u8 {
    if state == TargetState::NoResponse {
        0
    } else {
        (syn_attempts.min(15) << 4) | state.rank()
    }
}

pub(crate) fn decode_state_byte(value: u8) -> anyhow::Result<(TargetState, u8)> {
    let state = match value & 0x0f {
        0 => TargetState::NoResponse,
        1 => TargetState::Unreachable,
        2 => TargetState::Closed,
        3 => TargetState::Open,
        state => anyhow::bail!("invalid target state byte {value} with state code {state}"),
    };
    let attempts = value >> 4;
    Ok((state, attempts))
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
    #[serde(default)]
    pub conflicting_observations: u32,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_byte_preserves_legacy_state_values() -> anyhow::Result<()> {
        assert_eq!(decode_state_byte(1)?, (TargetState::Unreachable, 0));
        assert_eq!(decode_state_byte(2)?, (TargetState::Closed, 0));
        assert_eq!(decode_state_byte(3)?, (TargetState::Open, 0));
        Ok(())
    }

    #[test]
    fn state_byte_encodes_observed_attempts() -> anyhow::Result<()> {
        let value = encode_state_byte(TargetState::Open, 2);

        assert_eq!(decode_state_byte(value)?, (TargetState::Open, 2));
        Ok(())
    }
}
