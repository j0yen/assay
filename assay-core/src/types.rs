//! Core types for assay attestation reports.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A mechanism layer that was exercised during attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layer {
    /// The clone flag was accepted by the kernel (unshare returned Ok).
    FlagAccepted,
    /// A new agent namespace was successfully created.
    NsCreated,
    /// After namespace creation, the agent_session is non-zero.
    SessionNonZero,
    /// Agent counters advance after syscall activity inside the namespace.
    CountersAdvance,
    /// An intent tag can be set and retrieved via prctl.
    IntentTagRoundtrip,
}

impl Layer {
    /// Human-readable name for display.
    pub fn name(&self) -> &'static str {
        match self {
            Layer::FlagAccepted => "FlagAccepted",
            Layer::NsCreated => "NsCreated",
            Layer::SessionNonZero => "SessionNonZero",
            Layer::CountersAdvance => "CountersAdvance",
            Layer::IntentTagRoundtrip => "IntentTagRoundtrip",
        }
    }
}

/// The verdict localizing the first failed layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
pub enum Verdict {
    /// The unshare syscall was rejected by the kernel.
    FlagRejected {
        flag: u32,
        collides_with: Option<String>,
        errno: i32,
    },
    /// Namespace was created but the session ID stayed zero.
    NsCreatedButSessionZero,
    /// Namespace created and session set, but counters never moved.
    CountersDead,
    /// Intent tag was not preserved through prctl roundtrip.
    IntentTagLost,
    /// All layers passed — the mechanism is fully functional.
    Live { session: String },
    /// Unexpected error that does not fit the above categories.
    Unknown { detail: String },
}

impl Verdict {
    /// Returns the exit code encoding the verdict class.
    ///
    /// - `0`: Live (success)
    /// - `1`: FlagRejected
    /// - `2`: NsCreatedButSessionZero
    /// - `3`: CountersDead
    /// - `4`: IntentTagLost
    /// - `5`: Unknown
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Live { .. } => 0,
            Verdict::FlagRejected { .. } => 1,
            Verdict::NsCreatedButSessionZero => 2,
            Verdict::CountersDead => 3,
            Verdict::IntentTagLost => 4,
            Verdict::Unknown { .. } => 5,
        }
    }

    /// One-line remediation pointer for the human report.
    pub fn remediation(&self) -> &'static str {
        match self {
            Verdict::FlagRejected { .. } => {
                "kernel rejects the flag — see PRD-agentns-clone-flag-fix; wrapping the launch will not help"
            }
            Verdict::NsCreatedButSessionZero => {
                "flag accepted but session stays zero — kernel session-id assignment is broken; check agentns patch 0006"
            }
            Verdict::CountersDead => {
                "namespace created and session set but counters stalled — accounting hook missing; check agentns patch 0003"
            }
            Verdict::IntentTagLost => {
                "intent tag lost — prctl handler not wired; check agentns patch 0005"
            }
            Verdict::Live { .. } => "no remediation needed — mechanism is fully functional",
            Verdict::Unknown { .. } => "unexpected error — check evidence for details",
        }
    }
}

/// Key-value evidence records supporting the verdict.
pub type Evidence = BTreeMap<String, String>;

/// A complete attestation report for one primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestReport {
    /// The primitive that was attested (e.g. "agentns").
    pub primitive: String,
    /// The verdict localizing the first failed layer.
    pub verdict: Verdict,
    /// Layers that passed before the first failure (or all layers if Live).
    pub layers_passed: Vec<Layer>,
    /// Raw evidence that the verdict was derived from.
    pub evidence: Evidence,
    /// Kernel release string (`uname -r`).
    pub kernel_release: String,
    /// RFC 3339 timestamp when the attestation was performed.
    pub checked_at: String,
}
