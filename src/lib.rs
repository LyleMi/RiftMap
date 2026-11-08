//! Reusable core for RiftMap. Network transmission is Linux-only; target
//! preparation, parsing and export are portable and intentionally testable.

pub mod config;
pub mod distributed;
pub mod job;
pub mod ops;
pub mod packet;
pub mod permutation;
pub mod protocol;
pub mod rate;
pub mod result;
pub mod scanner;
pub mod target;

pub use config::{Config, Protocol};
pub use result::{BannerStatus, ResultV1, TargetState};

pub const SCHEMA_VERSION: u32 = 1;
