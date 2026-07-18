//! Small-domain keyed permutation using a balanced Feistel network and cycle walking.
use blake3::Hasher;

#[derive(Clone)]
pub struct Permutation {
    n: u64,
    bits: u32,
    half: u32,
    mask: u64,
    key: [u8; 32],
}
impl Permutation {
    pub fn new(n: u64, seed: [u8; 32]) -> anyhow::Result<Self> {
        anyhow::ensure!(n > 0, "permutation domain cannot be empty");
        let needed = (64 - (n - 1).leading_zeros()).max(1);
        let bits = if needed % 2 == 0 { needed } else { needed + 1 };
        anyhow::ensure!(bits <= 64, "domain too large");
        let half = bits / 2;
        let mask = if half == 64 {
            u64::MAX
        } else {
            (1u64 << half) - 1
        };
        Ok(Self {
            n,
            bits,
            half,
            mask,
            key: seed,
        })
    }
    fn round(&self, right: u64, round: u8) -> u64 {
        let mut h = Hasher::new_keyed(&self.key);
        h.update(&[round]);
        h.update(&right.to_le_bytes());
        u64::from_le_bytes(h.finalize().as_bytes()[..8].try_into().unwrap()) & self.mask
    }
    fn full(&self, x: u64) -> u64 {
        let mut l = x >> self.half;
        let mut r = x & self.mask;
        for round in 0..6 {
            (l, r) = (r, (l ^ self.round(r, round)) & self.mask);
        }
        (l << self.half) | r
    }
    pub fn get(&self, index: u64) -> u64 {
        assert!(index < self.n);
        if self.n == 1 {
            return 0;
        }
        let mut x = index;
        loop {
            x = self.full(x);
            if x < self.n {
                return x;
            }
        }
    }
    pub fn domain_bits(&self) -> u32 {
        self.bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    #[test]
    fn bijective_and_stable() {
        for n in 1..300 {
            let p = Permutation::new(n, [7; 32]).unwrap();
            let values: HashSet<_> = (0..n).map(|i| p.get(i)).collect();
            assert_eq!(values.len() as u64, n);
            assert!(values.iter().all(|v| *v < n));
        }
        assert_eq!(
            Permutation::new(10, [1; 32]).unwrap().get(4),
            Permutation::new(10, [1; 32]).unwrap().get(4)
        );
    }
}
