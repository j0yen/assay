//! Core types and attestation logic for the assay tool.
//!
//! The primary entry point is [`agentns::attest`], which runs the
//! agentns attestation using the provided [`AgentSyscalls`] implementation.

pub mod agentns;
pub mod types;

pub use types::{AttestReport, Evidence, Layer, Verdict};
