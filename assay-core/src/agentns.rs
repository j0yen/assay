//! Agentns attestation — exercises the kernel agentns mechanism in a
//! throwaway child process and returns a structured verdict.
//!
//! The syscall surface is abstracted behind [`AgentSyscalls`] so unit tests
//! can inject scripted responses without needing a special kernel.

use crate::types::{AttestReport, Evidence, Layer, Verdict};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// prctl constants from agentns/include/uapi/linux/agent_namespaces.h
//
// PR_AGENT_BASE = 0x41544E53 ("ATNS" magic).  All agent prctl operations
// are dispatched off this base.  The patch wires PR_SET_AGENT_NS (base+7)
// into kernel/sys.c and routes it through agentns_create_ns().
//
// Namespace creation goes through prctl(PR_SET_AGENT_NS), NOT through
// unshare(CLONE_NEWAGENT): the legacy 32-bit clone-flag space is
// exhausted (CLONE_NEWAGENT_HEADER == 0x100 == CLONE_VM), so there is no
// free bit to hang a new namespace off.  prctl has a separate dispatch
// table with ample room.
// ---------------------------------------------------------------------------

/// prctl base shared by all agent-namespace operations ("ATNS").
pub const PR_AGENT_BASE: libc::c_int = 0x41544E53u32 as libc::c_int;

/// prctl(PR_SET_AGENT_NS, 0, 0, 0, 0) — create-and-enter a fresh agent NS.
/// Requires CAP_SYS_ADMIN.
pub const PR_SET_AGENT_NS: libc::c_int = PR_AGENT_BASE + 7;

/// prctl(PR_SET_AGENT_INTENT_TAG) — store an intent tag in the current NS.
const PR_SET_AGENT_INTENT_TAG: libc::c_int = PR_AGENT_BASE + 2;

/// prctl(PR_GET_AGENT_INTENT_TAG) — retrieve the intent tag.
const PR_GET_AGENT_INTENT_TAG: libc::c_int = PR_AGENT_BASE + 3;

// ---------------------------------------------------------------------------
// Syscall abstraction
// ---------------------------------------------------------------------------

/// Abstracts the raw kernel syscalls so unit tests can inject fake behaviour.
pub trait AgentSyscalls {
    /// Read /proc/self/agent_session (32-hex-char string or all-zeros).
    fn read_agent_session(&self) -> std::io::Result<String>;

    /// Call prctl(PR_SET_AGENT_NS) to create and enter a fresh agent NS.
    /// Returns errno (0 = success, EPERM = needs CAP_SYS_ADMIN).
    fn create_agent_ns(&self) -> i32;

    /// Read /proc/self/agent_counters.
    fn read_agent_counters(&self) -> std::io::Result<AgentCounters>;

    /// Set + get intent tag via prctl.  Returns the retrieved tag on success.
    fn intent_tag_roundtrip(&self, tag: u64) -> std::io::Result<u64>;

    /// Perform some counted syscall activity so counters can advance.
    fn do_activity(&self) {}
}

/// Counter snapshot from /proc/self/agent_counters.
#[derive(Debug, Default, Clone)]
pub struct AgentCounters {
    pub syscalls: u64,
    pub bytes_written: u64,
}

// ---------------------------------------------------------------------------
// Live (real) implementation
// ---------------------------------------------------------------------------

pub struct LiveSyscalls;

impl AgentSyscalls for LiveSyscalls {
    fn read_agent_session(&self) -> std::io::Result<String> {
        let raw = std::fs::read_to_string("/proc/self/agent_session")?;
        Ok(raw.trim().to_string())
    }

    fn create_agent_ns(&self) -> i32 {
        let ret = unsafe { libc::prctl(PR_SET_AGENT_NS, 0, 0, 0, 0) };
        if ret == 0 {
            0
        } else {
            let e = std::io::Error::last_os_error();
            e.raw_os_error().unwrap_or(-1)
        }
    }

    fn read_agent_counters(&self) -> std::io::Result<AgentCounters> {
        let raw = std::fs::read_to_string("/proc/self/agent_counters")?;
        Ok(parse_agent_counters(&raw))
    }

    fn intent_tag_roundtrip(&self, tag: u64) -> std::io::Result<u64> {
        // The kernel uses copy_from_user/copy_to_user — pass a pointer, not the value.
        let mut tag_val = tag;
        let set_ret = unsafe {
            libc::prctl(
                PR_SET_AGENT_INTENT_TAG,
                &mut tag_val as *mut u64 as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if set_ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut out: u64 = 0;
        let get_ret = unsafe {
            libc::prctl(
                PR_GET_AGENT_INTENT_TAG,
                &mut out as *mut u64 as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        if get_ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(out)
    }

    fn do_activity(&self) {
        // Open /dev/null several times to bump syscall counter.
        for _ in 0..8 {
            let _ = std::fs::OpenOptions::new().read(true).open("/dev/null");
        }
    }
}

// ---------------------------------------------------------------------------
// Child-to-parent protocol over a pipe
// ---------------------------------------------------------------------------

/// Serialisable report sent from the child process to the parent.
#[derive(Debug)]
struct ChildReport {
    prctl_errno: i32,
    after_session: String,
    counters_before: AgentCounters,
    counters_after: AgentCounters,
    intent_tag_ok: bool,
}

fn encode_child_report(r: &ChildReport) -> Vec<u8> {
    // Simple fixed-layout binary: errno(4) + session(33) + cb_sys(8) +
    // cb_bytes(8) + ca_sys(8) + ca_bytes(8) + intent_ok(1)
    let mut buf = Vec::new();
    buf.extend_from_slice(&r.prctl_errno.to_le_bytes());
    let mut sess = [0u8; 33];
    let b = r.after_session.as_bytes();
    let n = b.len().min(32);
    sess[..n].copy_from_slice(&b[..n]);
    buf.extend_from_slice(&sess);
    buf.extend_from_slice(&r.counters_before.syscalls.to_le_bytes());
    buf.extend_from_slice(&r.counters_before.bytes_written.to_le_bytes());
    buf.extend_from_slice(&r.counters_after.syscalls.to_le_bytes());
    buf.extend_from_slice(&r.counters_after.bytes_written.to_le_bytes());
    buf.push(if r.intent_tag_ok { 1 } else { 0 });
    buf
}

fn decode_child_report(buf: &[u8]) -> Option<ChildReport> {
    if buf.len() < 4 + 33 + 8 + 8 + 8 + 8 + 1 {
        return None;
    }
    let errno = i32::from_le_bytes(buf[0..4].try_into().ok()?);
    let sess_bytes = &buf[4..37];
    let after_session = std::str::from_utf8(sess_bytes)
        .unwrap_or("")
        .trim_matches('\0')
        .to_string();
    let mut off = 37;
    let cb_sys = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let cb_bytes = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let ca_sys = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let ca_bytes = u64::from_le_bytes(buf[off..off + 8].try_into().ok()?);
    off += 8;
    let intent_tag_ok = buf[off] != 0;
    Some(ChildReport {
        prctl_errno: errno,
        after_session,
        counters_before: AgentCounters {
            syscalls: cb_sys,
            bytes_written: cb_bytes,
        },
        counters_after: AgentCounters {
            syscalls: ca_sys,
            bytes_written: ca_bytes,
        },
        intent_tag_ok,
    })
}

// ---------------------------------------------------------------------------
// Core attestation logic (trait-based, testable)
// ---------------------------------------------------------------------------

/// Run the agentns attestation using the provided syscall interface.
pub fn attest_with<S: AgentSyscalls>(syscalls: &S) -> AttestReport {
    let before_session = syscalls
        .read_agent_session()
        .unwrap_or_else(|_| "error".to_string());

    let mut evidence = Evidence::new();
    evidence.insert("before_session".into(), before_session.clone());
    evidence.insert(
        "creation_method".into(),
        format!("prctl(PR_SET_AGENT_NS={:#x})", PR_SET_AGENT_NS),
    );

    let prctl_errno = syscalls.create_agent_ns();
    evidence.insert("prctl_errno".into(), prctl_errno.to_string());

    if prctl_errno != 0 {
        let verdict = Verdict::FlagRejected {
            flag: PR_SET_AGENT_NS as u32,
            collides_with: None,
            errno: prctl_errno,
        };
        return build_report("agentns", verdict, vec![], evidence);
    }

    // prctl succeeded.
    let after_session = syscalls
        .read_agent_session()
        .unwrap_or_else(|_| "error".to_string());
    evidence.insert("after_session".into(), after_session.clone());

    let layers_passed_flag = vec![Layer::FlagAccepted, Layer::NsCreated];

    let session_zero = after_session == "00000000000000000000000000000000"
        || after_session.chars().all(|c| c == '0');
    if session_zero {
        return build_report(
            "agentns",
            Verdict::NsCreatedButSessionZero,
            layers_passed_flag,
            evidence,
        );
    }

    let mut layers_passed_session = layers_passed_flag;
    layers_passed_session.push(Layer::SessionNonZero);

    // Counters
    let counters_before = syscalls.read_agent_counters().unwrap_or_default();
    syscalls.do_activity();
    let counters_after = syscalls.read_agent_counters().unwrap_or_default();

    evidence.insert(
        "counters_before".into(),
        format!(
            "syscalls={} bytes={}",
            counters_before.syscalls, counters_before.bytes_written
        ),
    );
    evidence.insert(
        "counters_after".into(),
        format!(
            "syscalls={} bytes={}",
            counters_after.syscalls, counters_after.bytes_written
        ),
    );

    if counters_after.syscalls <= counters_before.syscalls {
        return build_report(
            "agentns",
            Verdict::CountersDead,
            layers_passed_session,
            evidence,
        );
    }

    let mut layers_passed_counters = layers_passed_session;
    layers_passed_counters.push(Layer::CountersAdvance);

    // Intent tag roundtrip
    let tag_result = syscalls.intent_tag_roundtrip(0xdeadbeef_cafebabe);
    let intent_tag_ok = tag_result
        .map(|v| v == 0xdeadbeef_cafebabe)
        .unwrap_or(false);
    evidence.insert("intent_tag_ok".into(), intent_tag_ok.to_string());

    if !intent_tag_ok {
        return build_report(
            "agentns",
            Verdict::IntentTagLost,
            layers_passed_counters,
            evidence,
        );
    }

    let mut layers_all = layers_passed_counters;
    layers_all.push(Layer::IntentTagRoundtrip);

    build_report(
        "agentns",
        Verdict::Live {
            session: after_session,
        },
        layers_all,
        evidence,
    )
}

fn build_report(
    primitive: &str,
    verdict: Verdict,
    layers_passed: Vec<Layer>,
    evidence: Evidence,
) -> AttestReport {
    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let checked_at = {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_rfc3339(secs)
    };

    AttestReport {
        primitive: primitive.to_string(),
        verdict,
        layers_passed,
        evidence,
        kernel_release,
        checked_at,
    }
}

fn format_rfc3339(unix_secs: u64) -> String {
    let s = unix_secs;
    let days = s / 86400;
    let rem = s % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, hh, mm, ss)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut d = days + 719468;
    let era = d / 146097;
    d %= 146097;
    let yoe = (d - d / 1460 + d / 36524 - d / 146096) / 365;
    let y = yoe + era * 400;
    let doy = d - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dom = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };
    (year, mo, dom)
}

// ---------------------------------------------------------------------------
// The forking live attestation (used by the CLI)
// ---------------------------------------------------------------------------

/// Run the agentns attestation by forking a child process.
///
/// The child calls `prctl(PR_SET_AGENT_NS)` and reports its findings back to
/// the parent over a pipe.  The parent's own agent_session is never mutated
/// (the namespace dies with the child).
pub fn attest_live() -> AttestReport {
    let before_session = std::fs::read_to_string("/proc/self/agent_session")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string());

    let mut evidence = Evidence::new();
    evidence.insert(
        "creation_method".into(),
        format!("prctl(PR_SET_AGENT_NS={:#x})", PR_SET_AGENT_NS),
    );
    evidence.insert("before_session".into(), before_session.clone());

    // Create pipe for child→parent communication.
    let rc;
    let pipe_r: libc::c_int;
    let pipe_w: libc::c_int;
    unsafe {
        let mut fds = [0i32; 2];
        rc = libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC);
        pipe_r = fds[0];
        pipe_w = fds[1];
    }

    if rc != 0 {
        evidence.insert(
            "pipe_error".into(),
            std::io::Error::last_os_error().to_string(),
        );
        return build_report(
            "agentns",
            Verdict::Unknown {
                detail: "pipe() failed".to_string(),
            },
            vec![],
            evidence,
        );
    }

    let child_pid = unsafe { libc::fork() };
    match child_pid {
        -1 => {
            unsafe { libc::close(pipe_r) };
            unsafe { libc::close(pipe_w) };
            evidence.insert(
                "fork_error".into(),
                std::io::Error::last_os_error().to_string(),
            );
            build_report(
                "agentns",
                Verdict::Unknown {
                    detail: "fork() failed".to_string(),
                },
                vec![],
                evidence,
            )
        }
        0 => {
            // Child process.
            unsafe { libc::close(pipe_r) };

            // Create a fresh agent namespace via prctl(PR_SET_AGENT_NS).
            let prctl_ret = unsafe { libc::prctl(PR_SET_AGENT_NS, 0, 0, 0, 0) };
            let prctl_errno = if prctl_ret == 0 {
                0i32
            } else {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(-1)
            };

            let after_session = if prctl_errno == 0 {
                std::fs::read_to_string("/proc/self/agent_session")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "error".to_string())
            } else {
                String::new()
            };

            let counters_before = read_counters_raw();

            for _ in 0..8 {
                let _ = std::fs::OpenOptions::new().read(true).open("/dev/null");
            }

            let counters_after = read_counters_raw();

            let intent_tag_ok = if prctl_errno == 0 {
                // Kernel uses copy_from_user/copy_to_user — pass a pointer.
                let mut tag_val: u64 = 0xdeadbeef_cafebabe;
                let set_ret = unsafe {
                    libc::prctl(
                        PR_SET_AGENT_INTENT_TAG,
                        &mut tag_val as *mut u64 as libc::c_ulong,
                        0,
                        0,
                        0,
                    )
                };
                if set_ret == 0 {
                    let mut out: u64 = 0;
                    let get_ret = unsafe {
                        libc::prctl(
                            PR_GET_AGENT_INTENT_TAG,
                            &mut out as *mut u64 as libc::c_ulong,
                            0,
                            0,
                            0,
                        )
                    };
                    get_ret == 0 && out == 0xdeadbeef_cafebabe
                } else {
                    false
                }
            } else {
                false
            };

            let report = ChildReport {
                prctl_errno,
                after_session,
                counters_before,
                counters_after,
                intent_tag_ok,
            };
            let payload = encode_child_report(&report);

            use std::os::unix::io::FromRawFd;
            let mut writer = unsafe { std::fs::File::from_raw_fd(pipe_w) };
            let _ = writer.write_all(&payload);
            drop(writer);

            unsafe { libc::_exit(0) };
        }
        child_pid => {
            // Parent process.
            unsafe { libc::close(pipe_w) };

            use std::os::unix::io::FromRawFd;
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_r) };
            let mut payload = Vec::new();
            let _ = reader.read_to_end(&mut payload);
            drop(reader);

            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };

            let parent_session_after = std::fs::read_to_string("/proc/self/agent_session")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unavailable".to_string());
            evidence.insert("parent_session_after".into(), parent_session_after.clone());
            evidence.insert(
                "parent_session_unchanged".into(),
                (parent_session_after == before_session).to_string(),
            );

            let Some(child) = decode_child_report(&payload) else {
                return build_report(
                    "agentns",
                    Verdict::Unknown {
                        detail: "failed to decode child report".to_string(),
                    },
                    vec![],
                    evidence,
                );
            };

            evidence.insert("prctl_errno".into(), child.prctl_errno.to_string());
            evidence.insert("after_session".into(), child.after_session.clone());
            evidence.insert(
                "counters_before".into(),
                format!(
                    "syscalls={} bytes={}",
                    child.counters_before.syscalls, child.counters_before.bytes_written
                ),
            );
            evidence.insert(
                "counters_after".into(),
                format!(
                    "syscalls={} bytes={}",
                    child.counters_after.syscalls, child.counters_after.bytes_written
                ),
            );
            evidence.insert("intent_tag_ok".into(), child.intent_tag_ok.to_string());

            if child.prctl_errno != 0 {
                return build_report(
                    "agentns",
                    Verdict::FlagRejected {
                        flag: PR_SET_AGENT_NS as u32,
                        collides_with: None,
                        errno: child.prctl_errno,
                    },
                    vec![],
                    evidence,
                );
            }

            let layers_passed_flag = vec![Layer::FlagAccepted, Layer::NsCreated];

            let session_zero = child.after_session == "00000000000000000000000000000000"
                || child.after_session.chars().all(|c| c == '0');
            if session_zero {
                return build_report(
                    "agentns",
                    Verdict::NsCreatedButSessionZero,
                    layers_passed_flag,
                    evidence,
                );
            }

            let mut layers = layers_passed_flag;
            layers.push(Layer::SessionNonZero);

            if child.counters_after.syscalls <= child.counters_before.syscalls {
                return build_report("agentns", Verdict::CountersDead, layers, evidence);
            }
            layers.push(Layer::CountersAdvance);

            if !child.intent_tag_ok {
                return build_report("agentns", Verdict::IntentTagLost, layers, evidence);
            }
            layers.push(Layer::IntentTagRoundtrip);

            build_report(
                "agentns",
                Verdict::Live {
                    session: child.after_session,
                },
                layers,
                evidence,
            )
        }
    }
}

fn read_counters_raw() -> AgentCounters {
    let raw = match std::fs::read_to_string("/proc/self/agent_counters") {
        Ok(s) => s,
        Err(_) => return AgentCounters::default(),
    };
    parse_agent_counters(&raw)
}

/// Parse /proc/self/agent_counters JSON.
///
/// The kernel emits: total_syscalls, openat_count, write_bytes,
/// connect_count, unlink_count, fork_count, elapsed_ns.
/// `total_syscalls` is a separate bucket that may not count openat/write;
/// use `openat_count` as the primary "did any work?" signal since
/// the test opens /dev/null 8 times.
fn parse_agent_counters(raw: &str) -> AgentCounters {
    let mut c = AgentCounters::default();
    for line in raw.lines() {
        let line = line.trim().trim_end_matches(',');
        if let Some((key_part, val_part)) = line.split_once(':') {
            let key = key_part.trim().trim_matches('"');
            let val: u64 = val_part.trim().parse().unwrap_or(0);
            match key {
                // openat_count advances when we open files — use as "syscalls" proxy.
                "openat_count" => c.syscalls = c.syscalls.saturating_add(val),
                "total_syscalls" => c.syscalls = c.syscalls.saturating_add(val),
                "write_bytes" => c.bytes_written = val,
                _ => {}
            }
        }
    }
    c
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSyscalls {
        prctl_errno: i32,
        session_before: String,
        session_after: String,
        counters_before: AgentCounters,
        counters_after: AgentCounters,
        intent_tag_ok: bool,
    }

    impl FakeSyscalls {
        fn rejected(errno: i32) -> Self {
            FakeSyscalls {
                prctl_errno: errno,
                session_before: "0".repeat(32),
                session_after: String::new(),
                counters_before: AgentCounters::default(),
                counters_after: AgentCounters::default(),
                intent_tag_ok: false,
            }
        }

        fn live_full() -> Self {
            FakeSyscalls {
                prctl_errno: 0,
                session_before: "0".repeat(32),
                session_after: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".to_string(),
                counters_before: AgentCounters {
                    syscalls: 10,
                    bytes_written: 0,
                },
                counters_after: AgentCounters {
                    syscalls: 20,
                    bytes_written: 0,
                },
                intent_tag_ok: true,
            }
        }

        fn ns_created_session_zero() -> Self {
            FakeSyscalls {
                prctl_errno: 0,
                session_before: "0".repeat(32),
                session_after: "0".repeat(32),
                counters_before: AgentCounters::default(),
                counters_after: AgentCounters::default(),
                intent_tag_ok: false,
            }
        }
    }

    /// Stateful fake that returns different values for before/after reads.
    struct StatefulFake {
        session_call: std::cell::Cell<u32>,
        counters_call: std::cell::Cell<u32>,
        inner: FakeSyscalls,
    }

    impl StatefulFake {
        fn new(inner: FakeSyscalls) -> Self {
            StatefulFake {
                session_call: std::cell::Cell::new(0),
                counters_call: std::cell::Cell::new(0),
                inner,
            }
        }
    }

    impl AgentSyscalls for FakeSyscalls {
        fn read_agent_session(&self) -> std::io::Result<String> {
            Ok(self.session_before.clone())
        }
        fn create_agent_ns(&self) -> i32 {
            self.prctl_errno
        }
        fn read_agent_counters(&self) -> std::io::Result<AgentCounters> {
            Ok(self.counters_before.clone())
        }
        fn intent_tag_roundtrip(&self, _tag: u64) -> std::io::Result<u64> {
            if self.intent_tag_ok {
                Ok(0xdeadbeef_cafebabe)
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EINVAL))
            }
        }
    }

    impl AgentSyscalls for StatefulFake {
        fn read_agent_session(&self) -> std::io::Result<String> {
            let n = self.session_call.get();
            self.session_call.set(n + 1);
            if n == 0 {
                Ok(self.inner.session_before.clone())
            } else {
                Ok(self.inner.session_after.clone())
            }
        }
        fn create_agent_ns(&self) -> i32 {
            self.inner.prctl_errno
        }
        fn read_agent_counters(&self) -> std::io::Result<AgentCounters> {
            let n = self.counters_call.get();
            self.counters_call.set(n + 1);
            if n == 0 {
                Ok(self.inner.counters_before.clone())
            } else {
                Ok(self.inner.counters_after.clone())
            }
        }
        fn intent_tag_roundtrip(&self, tag: u64) -> std::io::Result<u64> {
            self.inner.intent_tag_roundtrip(tag)
        }
        fn do_activity(&self) {}
    }

    #[test]
    fn test_live_all_layers() {
        let fake = StatefulFake::new(FakeSyscalls::live_full());
        let report = attest_with(&fake);
        assert!(
            matches!(report.verdict, Verdict::Live { .. }),
            "expected Live, got {:?}",
            report.verdict
        );
        assert_eq!(
            report.layers_passed.len(),
            5,
            "expected all 5 layers passed, got {:?}",
            report.layers_passed
        );
        assert!(report.layers_passed.contains(&Layer::FlagAccepted));
        assert!(report.layers_passed.contains(&Layer::NsCreated));
        assert!(report.layers_passed.contains(&Layer::SessionNonZero));
        assert!(report.layers_passed.contains(&Layer::CountersAdvance));
        assert!(report.layers_passed.contains(&Layer::IntentTagRoundtrip));
    }

    #[test]
    fn test_ns_created_session_zero() {
        let fake = FakeSyscalls::ns_created_session_zero();
        let report = attest_with(&fake);
        assert_eq!(
            report.verdict,
            Verdict::NsCreatedButSessionZero,
            "expected NsCreatedButSessionZero, got {:?}",
            report.verdict
        );
    }

    #[test]
    fn test_prctl_rejected_eperm() {
        let fake = FakeSyscalls::rejected(libc::EPERM);
        let report = attest_with(&fake);
        match &report.verdict {
            Verdict::FlagRejected { errno, .. } => {
                assert_eq!(*errno, libc::EPERM);
            }
            other => panic!("expected FlagRejected, got {:?}", other),
        }
        assert_eq!(report.layers_passed.len(), 0);
    }

    #[test]
    fn test_exit_codes() {
        assert_eq!(
            Verdict::Live {
                session: "x".into()
            }
            .exit_code(),
            0
        );
        assert_eq!(
            Verdict::FlagRejected {
                flag: 0,
                collides_with: None,
                errno: 0
            }
            .exit_code(),
            1
        );
        assert_eq!(Verdict::NsCreatedButSessionZero.exit_code(), 2);
        assert_eq!(Verdict::CountersDead.exit_code(), 3);
        assert_eq!(Verdict::IntentTagLost.exit_code(), 4);
    }

    #[test]
    fn test_pr_set_agent_ns_value() {
        // Verify the prctl constant matches the kernel header definition.
        // PR_AGENT_BASE = 0x41544E53 ("ATNS"), PR_SET_AGENT_NS = base + 7.
        assert_eq!(PR_AGENT_BASE as u32, 0x41544E53u32);
        assert_eq!(PR_SET_AGENT_NS as u32, 0x41544E5Au32);
    }
}
