use crate::result::{FtpFields, MysqlFields, PostgresFields, RedisFields, SmtpFields, SshFields};
use crate::{BannerStatus, Protocol};

#[derive(Debug, Clone, Default)]
pub struct ParsedBanner {
    pub text: Option<String>,
    pub ssh: Option<SshFields>,
    pub ftp: Option<FtpFields>,
    pub mysql: Option<MysqlFields>,
    pub smtp: Option<SmtpFields>,
    pub redis: Option<RedisFields>,
    pub postgres: Option<PostgresFields>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshKexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
}

pub fn message_len(
    protocol: Protocol,
    data: &[u8],
    max: usize,
) -> Result<Option<usize>, BannerStatus> {
    if data.len() > max {
        return Err(BannerStatus::Oversized);
    }
    match protocol {
        Protocol::Ssh => Ok(data.iter().position(|&b| b == b'\n').map(|i| i + 1)),
        Protocol::Ftp => ftp_len(data),
        Protocol::Mysql => mysql_len(data, max),
        Protocol::Smtp => smtp_len(data),
        Protocol::Redis => redis_len(data),
        Protocol::Postgres => postgres_len(data, max),
    }
}

fn mysql_len(data: &[u8], max: usize) -> Result<Option<usize>, BannerStatus> {
    if data.len() < 4 {
        return Ok(None);
    }
    let n = data[0] as usize | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
    let total = n.checked_add(4).ok_or(BannerStatus::Oversized)?;
    if total > max {
        Err(BannerStatus::Oversized)
    } else if data.len() >= total {
        Ok(Some(total))
    } else {
        Ok(None)
    }
}

fn ftp_len(data: &[u8]) -> Result<Option<usize>, BannerStatus> {
    let Some(first_end) = line_end(data) else {
        return Ok(None);
    };
    if data.len() < 4 || !data[..3].iter().all(u8::is_ascii_digit) {
        return Err(BannerStatus::ProtocolMismatch);
    }
    if data[3] == b' ' {
        return Ok(Some(first_end));
    }
    if data[3] != b'-' {
        return Err(BannerStatus::ProtocolMismatch);
    }
    Ok(multiline_ftp_end(data, first_end))
}

fn line_end(data: &[u8]) -> Option<usize> {
    data.windows(2)
        .position(|window| window == b"\r\n")
        .map(|i| i + 2)
}

fn multiline_ftp_end(data: &[u8], first_end: usize) -> Option<usize> {
    let mut needle = [0; 4];
    needle[..3].copy_from_slice(&data[..3]);
    needle[3] = b' ';
    data[first_end..]
        .windows(needle.len())
        .position(|window| window == needle)
        .and_then(|offset| {
            let line_start = first_end + offset;
            line_end(&data[line_start..]).map(|length| line_start + length)
        })
}

fn smtp_len(data: &[u8]) -> Result<Option<usize>, BannerStatus> {
    let Some(first_end) = line_end(data) else {
        return Ok(None);
    };
    if data.len() < 4 || !data[..3].iter().all(u8::is_ascii_digit) {
        return Err(BannerStatus::ProtocolMismatch);
    }
    if data[3] == b' ' {
        return Ok(Some(first_end));
    }
    if data[3] != b'-' {
        return Err(BannerStatus::ProtocolMismatch);
    }
    Ok(multiline_ftp_end(data, first_end))
}

fn redis_len(data: &[u8]) -> Result<Option<usize>, BannerStatus> {
    match data.first() {
        Some(b'+') | Some(b'-') | Some(b':') => Ok(line_end(data)),
        Some(b'$') => redis_bulk_len(data),
        Some(b'*') => Ok(line_end(data)),
        Some(_) => Err(BannerStatus::ProtocolMismatch),
        None => Ok(None),
    }
}

fn redis_bulk_len(data: &[u8]) -> Result<Option<usize>, BannerStatus> {
    let Some(header_end) = line_end(data) else {
        return Ok(None);
    };
    let len = std::str::from_utf8(&data[1..header_end - 2])
        .map_err(|_| BannerStatus::ProtocolMismatch)?
        .parse::<isize>()
        .map_err(|_| BannerStatus::ProtocolMismatch)?;
    if len < 0 {
        return Ok(Some(header_end));
    }
    let total = header_end
        .checked_add(len as usize)
        .and_then(|value| value.checked_add(2))
        .ok_or(BannerStatus::Oversized)?;
    Ok((data.len() >= total).then_some(total))
}

fn postgres_len(data: &[u8], max: usize) -> Result<Option<usize>, BannerStatus> {
    if data.len() < 5 {
        return Ok(None);
    }
    let tag = data[0];
    if !tag.is_ascii_alphabetic() {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
    if len < 4 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let total = len.checked_add(1).ok_or(BannerStatus::Oversized)?;
    if total > max {
        Err(BannerStatus::Oversized)
    } else {
        Ok((data.len() >= total).then_some(total))
    }
}

pub fn parse(protocol: Protocol, data: &[u8]) -> Result<ParsedBanner, BannerStatus> {
    match protocol {
        Protocol::Ssh => {
            let line = data.strip_suffix(b"\n").unwrap_or(data);
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let s = std::str::from_utf8(line).map_err(|_| BannerStatus::ProtocolMismatch)?;
            let rest = s
                .strip_prefix("SSH-")
                .ok_or(BannerStatus::ProtocolMismatch)?;
            let (proto, software) = rest.split_once('-').ok_or(BannerStatus::ProtocolMismatch)?;
            let (software, comments) = software
                .split_once(' ')
                .map_or((software, None), |(a, b)| (a, Some(b.to_owned())));
            Ok(ParsedBanner {
                text: Some(s.into()),
                ssh: Some(SshFields {
                    protocol_version: Some(proto.into()),
                    software_version: Some(software.into()),
                    comments,
                    implementation: ssh_implementation(software).map(str::to_owned),
                    implementation_version: ssh_implementation_version(software).map(str::to_owned),
                    ..Default::default()
                }),
                ..Default::default()
            })
        }
        Protocol::Ftp => {
            if data.len() < 3 || &data[..3] != b"220" {
                return Err(BannerStatus::ProtocolMismatch);
            }
            Ok(ParsedBanner {
                text: Some(String::from_utf8_lossy(data).trim_end().into()),
                ftp: Some(FtpFields {
                    code: Some(220),
                    multiline: data.get(3) == Some(&b'-'),
                }),
                ..Default::default()
            })
        }
        Protocol::Mysql => parse_mysql(data),
        Protocol::Smtp => parse_smtp(data),
        Protocol::Redis => parse_redis(data),
        Protocol::Postgres => parse_postgres(data),
    }
}

fn ssh_implementation(software: &str) -> Option<&str> {
    let prefixes = [
        "OpenSSH",
        "Dropbear",
        "libssh",
        "Cisco",
        "RomSShell",
        "PuTTY",
        "AsyncSSH",
    ];
    prefixes
        .iter()
        .copied()
        .find(|prefix| software.starts_with(prefix))
}

fn ssh_implementation_version(software: &str) -> Option<&str> {
    let implementation = ssh_implementation(software)?;
    software
        .strip_prefix(implementation)
        .and_then(|rest| rest.strip_prefix('_').or_else(|| rest.strip_prefix('-')))
        .filter(|version| !version.is_empty())
}

pub fn parse_ssh_kexinit_packet(data: &[u8]) -> Result<SshKexInit, BannerStatus> {
    let payload = ssh_packet_payload(data)?;
    if payload.first() != Some(&20) {
        return Err(BannerStatus::ProtocolMismatch);
    }
    if payload.len() < 17 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let mut cursor = 17;
    let kex_algorithms = read_ssh_namelist(payload, &mut cursor)?;
    let server_host_key_algorithms = read_ssh_namelist(payload, &mut cursor)?;
    let encryption_algorithms_client_to_server = read_ssh_namelist(payload, &mut cursor)?;
    let encryption_algorithms_server_to_client = read_ssh_namelist(payload, &mut cursor)?;
    let mac_algorithms_client_to_server = read_ssh_namelist(payload, &mut cursor)?;
    let mac_algorithms_server_to_client = read_ssh_namelist(payload, &mut cursor)?;
    let compression_algorithms_client_to_server = read_ssh_namelist(payload, &mut cursor)?;
    let compression_algorithms_server_to_client = read_ssh_namelist(payload, &mut cursor)?;
    let _languages_client_to_server = read_ssh_namelist(payload, &mut cursor)?;
    let _languages_server_to_client = read_ssh_namelist(payload, &mut cursor)?;
    if payload.len().saturating_sub(cursor) < 5 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    Ok(SshKexInit {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_client_to_server,
        encryption_algorithms_server_to_client,
        mac_algorithms_client_to_server,
        mac_algorithms_server_to_client,
        compression_algorithms_client_to_server,
        compression_algorithms_server_to_client,
    })
}

fn ssh_packet_payload(data: &[u8]) -> Result<&[u8], BannerStatus> {
    if data.len() < 5 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let packet_len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    let padding_len = data[4] as usize;
    let total = packet_len.checked_add(4).ok_or(BannerStatus::Oversized)?;
    if total != data.len() || packet_len < padding_len + 1 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let payload_len = packet_len - padding_len - 1;
    Ok(&data[5..5 + payload_len])
}

fn read_ssh_namelist(data: &[u8], cursor: &mut usize) -> Result<Vec<String>, BannerStatus> {
    if data.len().saturating_sub(*cursor) < 4 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let len = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().unwrap()) as usize;
    *cursor += 4;
    if data.len().saturating_sub(*cursor) < len {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let raw = &data[*cursor..*cursor + len];
    *cursor += len;
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(raw).map_err(|_| BannerStatus::ProtocolMismatch)?;
    Ok(text.split(',').map(ToOwned::to_owned).collect())
}

fn parse_mysql(data: &[u8]) -> Result<ParsedBanner, BannerStatus> {
    if data.len() < 5 || data[3] != 0 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let payload = &data[4..];
    let protocol = payload[0];
    if protocol != 10 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let nul = payload[1..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(BannerStatus::ProtocolMismatch)?
        + 1;
    if payload.len() < nul + 5 {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let version = String::from_utf8_lossy(&payload[1..nul]).into_owned();
    let id = u32::from_le_bytes(payload[nul + 1..nul + 5].try_into().unwrap());
    let low = if payload.len() >= nul + 18 {
        u16::from_le_bytes(payload[nul + 14..nul + 16].try_into().unwrap()) as u32
    } else {
        0
    };
    let high = if payload.len() >= nul + 21 {
        (u16::from_le_bytes(payload[nul + 19..nul + 21].try_into().unwrap()) as u32) << 16
    } else {
        0
    };
    Ok(ParsedBanner {
        mysql: Some(MysqlFields {
            protocol_version: Some(protocol),
            server_version: Some(version),
            connection_id: Some(id),
            capabilities: Some(low | high),
        }),
        ..Default::default()
    })
}

fn parse_smtp(data: &[u8]) -> Result<ParsedBanner, BannerStatus> {
    if data.len() < 3 || &data[..3] != b"220" {
        return Err(BannerStatus::ProtocolMismatch);
    }
    let text = String::from_utf8_lossy(data).trim_end().to_string();
    let first_line = text.lines().next().unwrap_or_default();
    let domain = first_line
        .get(4..)
        .and_then(|rest| rest.split_whitespace().next())
        .map(ToOwned::to_owned);
    Ok(ParsedBanner {
        text: Some(text),
        smtp: Some(SmtpFields {
            code: Some(220),
            multiline: data.get(3) == Some(&b'-'),
            domain,
        }),
        ..Default::default()
    })
}

fn parse_redis(data: &[u8]) -> Result<ParsedBanner, BannerStatus> {
    let text = String::from_utf8_lossy(data).trim_end().to_string();
    let (kind, message) = match data.first() {
        Some(b'+') => ("status", text.get(1..).unwrap_or_default().to_owned()),
        Some(b'-') => ("error", text.get(1..).unwrap_or_default().to_owned()),
        Some(b':') => ("integer", text.get(1..).unwrap_or_default().to_owned()),
        Some(b'$') => ("bulk", text.clone()),
        Some(b'*') => ("array", text.clone()),
        _ => return Err(BannerStatus::ProtocolMismatch),
    };
    Ok(ParsedBanner {
        text: Some(text),
        redis: Some(RedisFields {
            kind: Some(kind.into()),
            message: Some(message),
        }),
        ..Default::default()
    })
}

fn parse_postgres(data: &[u8]) -> Result<ParsedBanner, BannerStatus> {
    let message_type = match data.first().copied() {
        Some(b'E') => "error",
        Some(b'N') => "notice",
        Some(b'R') => "authentication",
        Some(b'S') => "parameter_status",
        Some(b'K') => "backend_key_data",
        Some(_) => "message",
        None => return Err(BannerStatus::ProtocolMismatch),
    };
    let payload = &data[5..];
    let mut severity = None;
    let mut message = None;
    if data[0] == b'E' || data[0] == b'N' {
        for field in payload
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
        {
            match field.split_first() {
                Some((b'S', value)) => severity = Some(String::from_utf8_lossy(value).into()),
                Some((b'M', value)) => message = Some(String::from_utf8_lossy(value).into()),
                _ => {}
            }
        }
    }
    Ok(ParsedBanner {
        text: message.clone(),
        postgres: Some(PostgresFields {
            message_type: Some(message_type.into()),
            severity,
            message,
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_fragment_and_parse() {
        assert_eq!(message_len(Protocol::Ssh, b"SSH-2.0-x", 99).unwrap(), None);
        let b = b"SSH-2.0-OpenSSH_9.0 hello\r\n";
        assert_eq!(message_len(Protocol::Ssh, b, 99).unwrap(), Some(b.len()));
        let ssh = parse(Protocol::Ssh, b).unwrap().ssh.unwrap();
        assert_eq!(ssh.software_version.as_deref(), Some("OpenSSH_9.0"));
        assert_eq!(ssh.implementation.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.implementation_version.as_deref(), Some("9.0"));
    }

    #[test]
    fn ssh_kexinit_packet_parses_algorithm_lists() {
        let mut payload = vec![20];
        payload.extend_from_slice(&[7; 16]);
        test_namelist(
            &mut payload,
            "curve25519-sha256,diffie-hellman-group14-sha256",
        );
        test_namelist(&mut payload, "ssh-ed25519,rsa-sha2-256");
        test_namelist(&mut payload, "aes128-ctr");
        test_namelist(&mut payload, "aes256-ctr");
        test_namelist(&mut payload, "hmac-sha2-256");
        test_namelist(&mut payload, "hmac-sha1");
        test_namelist(&mut payload, "none");
        test_namelist(&mut payload, "zlib@openssh.com,none");
        test_namelist(&mut payload, "");
        test_namelist(&mut payload, "");
        payload.push(0);
        payload.extend_from_slice(&0u32.to_be_bytes());

        let padding_len = 4usize;
        let packet_len = payload.len() + padding_len + 1;
        let mut packet = Vec::new();
        packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
        packet.push(padding_len as u8);
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(&[0; 4]);

        let kex = parse_ssh_kexinit_packet(&packet).unwrap();
        assert_eq!(kex.kex_algorithms[0], "curve25519-sha256");
        assert_eq!(kex.server_host_key_algorithms[1], "rsa-sha2-256");
        assert_eq!(
            kex.compression_algorithms_server_to_client,
            vec!["zlib@openssh.com", "none"]
        );
    }

    fn test_namelist(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    #[test]
    fn ftp_multiline() {
        let b = b"220-first\r\nfoo\r\n220 done\r\n";
        assert_eq!(message_len(Protocol::Ftp, b, 99).unwrap(), Some(b.len()));
        assert!(parse(Protocol::Ftp, b).unwrap().ftp.unwrap().multiline);
    }
    #[test]
    fn mysql_length_rejects_oversize() {
        assert_eq!(
            message_len(Protocol::Mysql, &[0xff, 0xff, 0x7f, 0], 4096),
            Err(BannerStatus::Oversized)
        );
    }
    #[test]
    fn mysql_parses_capability_halves() {
        let mut payload = vec![10];
        payload.extend_from_slice(b"8.0.36\0");
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.extend_from_slice(b"12345678");
        payload.push(0);
        payload.extend_from_slice(&0x1234u16.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&0x5678u16.to_le_bytes());
        let mut packet = vec![payload.len() as u8, 0, 0, 0];
        packet.extend_from_slice(&payload);
        let fields = parse(Protocol::Mysql, &packet).unwrap().mysql.unwrap();
        assert_eq!(fields.connection_id, Some(42));
        assert_eq!(fields.capabilities, Some(0x5678_1234));
    }

    #[test]
    fn smtp_multiline_parses_domain() {
        let b = b"220-mail.example ESMTP ready\r\n220-PIPELINING\r\n220 done\r\n";
        assert_eq!(message_len(Protocol::Smtp, b, 99).unwrap(), Some(b.len()));
        let fields = parse(Protocol::Smtp, b).unwrap().smtp.unwrap();
        assert_eq!(fields.code, Some(220));
        assert!(fields.multiline);
        assert_eq!(fields.domain.as_deref(), Some("mail.example"));
    }

    #[test]
    fn redis_parses_error_line() {
        let b = b"-ERR unknown command\r\n";
        assert_eq!(message_len(Protocol::Redis, b, 99).unwrap(), Some(b.len()));
        let fields = parse(Protocol::Redis, b).unwrap().redis.unwrap();
        assert_eq!(fields.kind.as_deref(), Some("error"));
        assert_eq!(fields.message.as_deref(), Some("ERR unknown command"));
    }

    #[test]
    fn postgres_parses_error_response() {
        let payload = b"SERROR\0Mbad startup\0\0";
        let len = (payload.len() + 4) as u32;
        let mut packet = vec![b'E'];
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);

        assert_eq!(
            message_len(Protocol::Postgres, &packet, 99).unwrap(),
            Some(packet.len())
        );
        let fields = parse(Protocol::Postgres, &packet)
            .unwrap()
            .postgres
            .unwrap();
        assert_eq!(fields.message_type.as_deref(), Some("error"));
        assert_eq!(fields.severity.as_deref(), Some("ERROR"));
        assert_eq!(fields.message.as_deref(), Some("bad startup"));
    }
}
