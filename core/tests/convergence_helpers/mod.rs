//! Reusable two-device convergence harness. See `convergence.rs`.
#![allow(dead_code)] // helpers land task-by-task; some are unused until later tasks

mod baseline;

pub use baseline::Baseline;
