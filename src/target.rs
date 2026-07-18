use anyhow::{Context, bail};
use std::{fs, net::Ipv4Addr, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Range {
    pub start: u32,
    pub end: u32,
}
impl Ipv4Range {
    pub fn len(self) -> u64 {
        u64::from(self.end) - u64::from(self.start) + 1
    }
    pub fn is_empty(self) -> bool {
        self.start > self.end
    }
}

pub fn parse_files(paths: &[impl AsRef<Path>]) -> anyhow::Result<Vec<Ipv4Range>> {
    let mut ranges = Vec::new();
    for path in paths {
        let path = path.as_ref();
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            ranges
                .push(parse_entry(line).with_context(|| format!("{}:{}", path.display(), i + 1))?);
        }
    }
    Ok(merge(ranges))
}

pub fn parse_entry(s: &str) -> anyhow::Result<Ipv4Range> {
    let (ip_s, prefix) = match s.split_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().context("invalid prefix")?),
        None => (s, 32),
    };
    if prefix > 32 {
        bail!("IPv4 prefix must be <= 32");
    }
    let ip: Ipv4Addr = ip_s.parse().context("invalid IPv4 address")?;
    let n = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(Ipv4Range {
        start: n & mask,
        end: (n & mask) | !mask,
    })
}

pub fn merge(mut ranges: Vec<Ipv4Range>) -> Vec<Ipv4Range> {
    ranges.sort_unstable_by_key(|r| r.start);
    let mut out: Vec<Ipv4Range> = Vec::new();
    for r in ranges {
        if let Some(last) = out.last_mut() {
            if u64::from(r.start) <= u64::from(last.end) + 1 {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        out.push(r);
    }
    out
}

pub fn subtract(includes: &[Ipv4Range], excludes: &[Ipv4Range]) -> Vec<Ipv4Range> {
    let mut out = Vec::new();
    let mut j = 0;
    for inc in includes {
        let mut cur = u64::from(inc.start);
        let end = u64::from(inc.end);
        while j < excludes.len() && excludes[j].end < inc.start {
            j += 1;
        }
        let mut k = j;
        while k < excludes.len() && u64::from(excludes[k].start) <= end {
            let ex = excludes[k];
            if u64::from(ex.start) > cur {
                out.push(Ipv4Range {
                    start: cur as u32,
                    end: (u64::from(ex.start) - 1) as u32,
                });
            }
            cur = cur.max(u64::from(ex.end) + 1);
            if cur > end {
                break;
            }
            k += 1;
        }
        if cur <= end {
            out.push(Ipv4Range {
                start: cur as u32,
                end: end as u32,
            });
        }
    }
    out
}

pub fn is_allowed(ip: Ipv4Addr, allow_private: bool) -> bool {
    let n = u32::from(ip);
    let in_net = |base: u32, bits: u8| n & (u32::MAX << (32 - bits)) == base;
    if n == 0
        || n == u32::MAX
        || in_net(0, 8)
        || in_net(0x7f00_0000, 8)
        || in_net(0xa9fe_0000, 16)
        || in_net(0xe000_0000, 4)
        || in_net(0xf000_0000, 4)
        || in_net(0x6440_0000, 10)
        || in_net(0xc000_0000, 24)
        || in_net(0xc000_0200, 24)
        || in_net(0xc612_0000, 15)
        || in_net(0xc633_6400, 24)
        || in_net(0xcb00_7100, 24)
        || in_net(0xc058_6300, 24)
    {
        return false;
    }
    let private = in_net(0x0a00_0000, 8) || in_net(0xac10_0000, 12) || in_net(0xc0a8_0000, 16);
    allow_private || !private
}

pub fn filter_allowed(ranges: &[Ipv4Range], allow_private: bool) -> Vec<Ipv4Range> {
    let cidr = |s: &str| parse_entry(s).unwrap();
    let mut denied = vec![
        cidr("0.0.0.0/8"),
        cidr("100.64.0.0/10"),
        cidr("127.0.0.0/8"),
        cidr("169.254.0.0/16"),
        cidr("192.0.0.0/24"),
        cidr("192.0.2.0/24"),
        cidr("192.88.99.0/24"),
        cidr("198.18.0.0/15"),
        cidr("198.51.100.0/24"),
        cidr("203.0.113.0/24"),
        cidr("224.0.0.0/4"),
        cidr("240.0.0.0/4"),
    ];
    if !allow_private {
        denied.extend([
            cidr("10.0.0.0/8"),
            cidr("172.16.0.0/12"),
            cidr("192.168.0.0/16"),
        ]);
    }
    subtract(ranges, &merge(denied))
}

pub fn count(ranges: &[Ipv4Range]) -> u64 {
    ranges.iter().map(|r| r.len()).sum()
}
pub fn iter(ranges: &[Ipv4Range]) -> impl Iterator<Item = Ipv4Addr> + '_ {
    ranges
        .iter()
        .flat_map(|r| (r.start..=r.end).map(Ipv4Addr::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_and_subtract_exactly() {
        let i = merge(vec![
            Ipv4Range { start: 1, end: 5 },
            Ipv4Range { start: 4, end: 9 },
            Ipv4Range { start: 11, end: 11 },
        ]);
        assert_eq!(
            i,
            vec![
                Ipv4Range { start: 1, end: 9 },
                Ipv4Range { start: 11, end: 11 }
            ]
        );
        assert_eq!(
            subtract(&i, &[Ipv4Range { start: 3, end: 7 }]),
            vec![
                Ipv4Range { start: 1, end: 2 },
                Ipv4Range { start: 8, end: 9 },
                Ipv4Range { start: 11, end: 11 }
            ]
        );
    }
    #[test]
    fn private_policy() {
        assert!(!is_allowed("10.0.0.1".parse().unwrap(), false));
        assert!(is_allowed("10.0.0.1".parse().unwrap(), true));
        assert!(!is_allowed("127.0.0.1".parse().unwrap(), true));
    }
}
