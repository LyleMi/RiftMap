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
    #[serde(default)]
    pub implementation: Option<String>,
    #[serde(default)]
    pub implementation_version: Option<String>,
    #[serde(default)]
    pub probe_mode: Option<String>,
    #[serde(default)]
    pub kex_algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub server_host_key_algorithms: Option<Vec<String>>,
    #[serde(default)]
    pub encryption_algorithms_client_to_server: Option<Vec<String>>,
    #[serde(default)]
    pub encryption_algorithms_server_to_client: Option<Vec<String>>,
    #[serde(default)]
    pub mac_algorithms_client_to_server: Option<Vec<String>>,
    #[serde(default)]
    pub mac_algorithms_server_to_client: Option<Vec<String>>,
    #[serde(default)]
    pub compression_algorithms_client_to_server: Option<Vec<String>>,
    #[serde(default)]
    pub compression_algorithms_server_to_client: Option<Vec<String>>,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SmtpFields {
    pub code: Option<u16>,
    pub multiline: bool,
    pub domain: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RedisFields {
    pub kind: Option<String>,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PostgresFields {
    pub message_type: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
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
    pub smtp: Option<SmtpFields>,
    pub redis: Option<RedisFields>,
    pub postgres: Option<PostgresFields>,
}

pub fn result_id(scan_id: &str, ip: std::net::Ipv4Addr, port: u16, protocol: Protocol) -> String {
    let mut h = blake3::Hasher::new();
    h.update(scan_id.as_bytes());
    h.update(&ip.octets());
    h.update(&port.to_be_bytes());
    h.update(&[crate::job::protocol_code(protocol)]);
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

    #[test]
    fn result_schema_file_is_valid_json() -> anyhow::Result<()> {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/result-v1.json"))?;

        assert_eq!(schema["title"], "RiftMap ResultV1");
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        Ok(())
    }

    #[test]
    fn legacy_result_without_conflicts_deserializes() -> anyhow::Result<()> {
        let result: ResultV1 = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "result_id": "result",
            "scan_id": "scan",
            "ip": "10.0.0.1",
            "port": 22,
            "protocol": "ssh",
            "state": "open",
            "syn_attempts": 1,
            "rtt_ms": 1.25,
            "first_observed_at": null,
            "last_observed_at": null,
            "banner_status": "ok",
            "banner_base64": null,
            "banner_text": "SSH-2.0-test",
            "ssh": null,
            "ftp": null,
            "mysql": null
        }))?;

        assert_eq!(result.conflicting_observations, 0);
        Ok(())
    }

    #[test]
    fn result_id_includes_protocol() {
        let ip = "10.0.0.1".parse().unwrap();

        assert_ne!(
            result_id("scan", ip, 22, Protocol::Ssh),
            result_id("scan", ip, 22, Protocol::Ftp)
        );
    }
}
