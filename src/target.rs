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
            ranges.extend(
                parse_entry_targets(line)
                    .with_context(|| format!("{}:{}", path.display(), i + 1))?,
            );
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

fn parse_entry_targets(s: &str) -> anyhow::Result<Vec<Ipv4Range>> {
    let range = parse_entry(s)?;
    let Some((_, prefix_s)) = s.split_once('/') else {
        return Ok(vec![range]);
    };
    let prefix = prefix_s.parse::<u8>().context("invalid prefix")?;
    if prefix <= 30 {
        Ok(trim_last_address(range))
    } else {
        Ok(vec![range])
    }
}

fn trim_last_address(range: Ipv4Range) -> Vec<Ipv4Range> {
    if range.start < range.end {
        vec![Ipv4Range {
            start: range.start,
            end: range.end - 1,
        }]
    } else {
        Vec::new()
    }
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
    let value = u32::from(ip);
    !denied_ranges(allow_private)
        .iter()
        .any(|range| range.start <= value && value <= range.end)
}

pub fn filter_allowed(ranges: &[Ipv4Range], allow_private: bool) -> Vec<Ipv4Range> {
    subtract(ranges, &merge(denied_ranges(allow_private)))
}

fn denied_ranges(allow_private: bool) -> Vec<Ipv4Range> {
    let mut denied = RESERVED_CIDRS
        .iter()
        .map(|&(base, bits)| cidr_range(base, bits))
        .collect::<Vec<_>>();
    if !allow_private {
        denied.extend(
            PRIVATE_CIDRS
                .iter()
                .map(|&(base, bits)| cidr_range(base, bits)),
        );
    }
    denied
}

fn cidr_range(base: u32, bits: u8) -> Ipv4Range {
    let host_mask = u32::MAX >> bits;
    Ipv4Range {
        start: base,
        end: base | host_mask,
    }
}

const RESERVED_CIDRS: &[(u32, u8)] = &[
    (0x0000_0000, 8),
    (0x6440_0000, 10),
    (0x7f00_0000, 8),
    (0xa9fe_0000, 16),
    (0xc000_0000, 24),
    (0xc000_0200, 24),
    (0xc058_6300, 24),
    (0xc612_0000, 15),
    (0xc633_6400, 24),
    (0xcb00_7100, 24),
    (0xe000_0000, 4),
    (0xf000_0000, 4),
];

const PRIVATE_CIDRS: &[(u32, u8)] = &[(0x0a00_0000, 8), (0xac10_0000, 12), (0xc0a8_0000, 16)];

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

    #[test]
    fn cidr_targets_drop_subnet_directed_broadcast() -> anyhow::Result<()> {
        let temp = tempfile::NamedTempFile::new()?;
        fs::write(temp.path(), "198.51.100.0/30\n")?;

        let ranges = parse_files(&[temp.path()])?;

        assert_eq!(
            ranges,
            vec![Ipv4Range {
                start: u32::from(Ipv4Addr::new(198, 51, 100, 0)),
                end: u32::from(Ipv4Addr::new(198, 51, 100, 2)),
            }]
        );
        Ok(())
    }

    #[test]
    fn cidr_targets_preserve_point_to_point_prefixes() -> anyhow::Result<()> {
        let temp = tempfile::NamedTempFile::new()?;
        fs::write(temp.path(), "198.51.100.0/31\n")?;

        let ranges = parse_files(&[temp.path()])?;

        assert_eq!(count(&ranges), 2);
        Ok(())
    }

    #[test]
    fn explicit_single_ip_keeps_dot_255_address() -> anyhow::Result<()> {
        let temp = tempfile::NamedTempFile::new()?;
        fs::write(temp.path(), "198.51.100.255\n")?;

        let ranges = parse_files(&[temp.path()])?;

        assert_eq!(
            ranges,
            vec![Ipv4Range {
                start: u32::from(Ipv4Addr::new(198, 51, 100, 255)),
                end: u32::from(Ipv4Addr::new(198, 51, 100, 255)),
            }]
        );
        Ok(())
    }
}
