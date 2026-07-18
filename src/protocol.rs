use crate::result::{FtpFields, MysqlFields, SshFields};
use crate::{BannerStatus, Protocol};

#[derive(Debug, Clone, Default)]
pub struct ParsedBanner {
    pub text: Option<String>,
    pub ssh: Option<SshFields>,
    pub ftp: Option<FtpFields>,
    pub mysql: Option<MysqlFields>,
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
        Protocol::Mysql => {
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
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_fragment_and_parse() {
        assert_eq!(message_len(Protocol::Ssh, b"SSH-2.0-x", 99).unwrap(), None);
        let b = b"SSH-2.0-OpenSSH_9.0 hello\r\n";
        assert_eq!(message_len(Protocol::Ssh, b, 99).unwrap(), Some(b.len()));
        assert_eq!(
            parse(Protocol::Ssh, b)
                .unwrap()
                .ssh
                .unwrap()
                .software_version
                .as_deref(),
            Some("OpenSSH_9.0")
        );
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
}
