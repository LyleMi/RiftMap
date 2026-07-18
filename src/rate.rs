use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_seconds: f64,
}
impl TokenBucket {
    pub fn new(bytes_per_second: f64, burst_seconds: f64) -> Self {
        let capacity = bytes_per_second * burst_seconds;
        Self {
            rate: bytes_per_second,
            capacity,
            tokens: capacity,
            last_seconds: 0.0,
        }
    }
    pub fn consume_at(&mut self, bytes: u64, now_seconds: f64) -> Duration {
        let requested_seconds = now_seconds;
        let accounted_seconds = requested_seconds.max(self.last_seconds);
        let elapsed = accounted_seconds - self.last_seconds;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            self.last_seconds = accounted_seconds;
            Duration::from_secs_f64(accounted_seconds - requested_seconds)
        } else {
            let d = (need - self.tokens) / self.rate;
            self.tokens = 0.0;
            self.last_seconds = accounted_seconds + d;
            Duration::from_secs_f64(self.last_seconds - requested_seconds)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simulated_clock() {
        let mut b = TokenBucket::new(100.0, 1.0);
        assert_eq!(b.consume_at(100, 0.0), Duration::ZERO);
        assert_eq!(b.consume_at(50, 0.0), Duration::from_millis(500));
        assert_eq!(b.consume_at(50, 1.0), Duration::ZERO);
    }

    #[test]
    fn future_reservations_accumulate() {
        let mut b = TokenBucket::new(100.0, 1.0);

        assert_eq!(b.consume_at(100, 0.0), Duration::ZERO);
        assert_eq!(b.consume_at(50, 0.0), Duration::from_millis(500));
        assert_eq!(b.consume_at(50, 0.0), Duration::from_secs(1));
    }
}
