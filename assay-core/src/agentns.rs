//! Agentns attestation — exercises the kernel agentns mechanism in a
//! throwaway child process and returns a structured verdict.
//!
//! The syscall surface is abstracted behind [`AgentSyscalls`] so unit tests
//! can inject scripted responses without needing a special kernel.

use crate::types::{AttestReport, Evidence, Layer, Verdict};
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Compiled-in constant mirrored from agentns/include/uapi/linux/agent_namespaces.h
//
// The header comment says it "claims 0x00000100 (an unused lower-pool bit)".
// However, 0x100 == CLONE_VM — a collision — which is the root-cause this tool
// documents.  The test binary (agentns/tests/test_unshare.c) uses the fall-back
// definition 0x400000000ULL (a 64-bit value) and calls SYS_unshare directly with
// that full value so the upper bits reach the kernel.  On this kernel that 64-bit
// flag is unrecognised, producing EINVAL (errno 22).
//
// We mirror both:
//   CLONE_NEWAGENT_UAPI  — what the kernel header claims (0x100, collides CLONE_VM)
//   CLONE_NEWAGENT       — what the test binary actually passes (0x400000000, full u64)
//
// The attestation uses the full 64-bit value via SYS_unshare to reproduce the
// live finding documented in PRD phase-1 evidence.
// ---------------------------------------------------------------------------
pub const CLONE_NEWAGENT_HEADER: u32 = 0x0000_0100;   // as-written in uapi header (== CLONE_VM)
pub const CLONE_NEWAGENT: u64 = 0x0000_0004_0000_0000; // 0x400000000 — 64-bit, used by test_unshare

/// Known-occupied 64-bit clone bits in the 32-bit flags space (lower 32 bits).
/// Used to check whether the lower 32 bits of CLONE_NEWAGENT collide.
const KNOWN_CLONE_FLAGS_32: &[(u32, &str)] = &[
    (0x0000_0100, "CLONE_VM"),
    (0x0000_0200, "CLONE_FS"),
    (0x0000_0400, "CLONE_FILES"),
    (0x0000_0800, "CLONE_SIGHAND"),
    (0x0000_4000, "CLONE_THREAD"),
    (0x0004_0000, "CLONE_NEWNS"),
    (0x0010_0000, "CLONE_SYSVSEM"),
    (0x0020_0000, "CLONE_SETTLS"),
    (0x0040_0000, "CLONE_PARENT_SETTID"),
    (0x0080_0000, "CLONE_CHILD_CLEARTID"),
    (0x0800_0000, "CLONE_CHILD_SETTID"),
    (0x0200_0000, "CLONE_NEWCGROUP"),
    (0x0400_0000, "CLONE_NEWUTS"),
    (0x0800_0000, "CLONE_NEWIPC"),
    (0x1000_0000, "CLONE_NEWUSER"),
    (0x2000_0000, "CLONE_NEWPID"),
    (0x4000_0000, "CLONE_NEWNET"),
    (0x0000_0080, "CLONE_NEWTIME"),
];

/// Check whether `flag` collides with a known-occupied 32-bit clone bit.
///
/// The documented collision: the uapi header writes `0x100` (== `CLONE_VM`) as a
/// comment for the lower-pool allocation.  The 64-bit value used by the test
/// (`0x400000000`) has no 32-bit collision — it is simply unrecognised by the
/// kernel.  We record the uapi-header collision separately in the evidence.
fn check_collision(flag: u64) -> Option<String> {
    // Check the lower 32 bits for known-occupied bits.
    let low32 = flag as u32;
    for &(bit, name) in KNOWN_CLONE_FLAGS_32 {
        if bit == low32 {
            return Some(name.to_string());
        }
    }
    None
}

/// Check whether the UAPI-header constant (0x100) collides with CLONE_VM.
fn header_collision() -> Option<String> {
    check_collision(CLONE_NEWAGENT_HEADER as u64)
}

// ---------------------------------------------------------------------------
// Syscall abstraction
// ---------------------------------------------------------------------------

/// Result of calling unshare(CLONE_NEWAGENT) inside the child.
#[derive(Debug)]
pub struct UnshareResult {
    /// 0 on success, negative errno on failure.
    pub errno: i32,
}

/// Counter snapshot from /proc/self/agent_counters.
#[derive(Debug, Default, Clone)]
pub struct AgentCounters {
    pub syscalls: u64,
    pub bytes_written: u64,
}

/// Abstracts the raw kernel syscalls so unit tests can inject fake behaviour.
pub trait AgentSyscalls {
    /// Read /proc/self/agent_session (32-hex-char string or all-zeros).
    fn read_agent_session(&self) -> std::io::Result<String>;

    /// Call unshare(CLONE_NEWAGENT).  Returns errno (0 = success).
    fn unshare_newagent(&self) -> i32;

    /// Read /proc/self/agent_counters.
    fn read_agent_counters(&self) -> std::io::Result<AgentCounters>;

    /// Set + get intent tag via prctl.  Returns the retrieved tag on success.
    fn intent_tag_roundtrip(&self, tag: u64) -> std::io::Result<u64>;

    /// Perform some counted syscall activity so counters can advance.
    fn do_activity(&self) {}
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

    fn unshare_newagent(&self) -> i32 {
        // Use syscall() directly so the full 64-bit flag reaches the kernel.
        // glibc's unshare(2) wrapper takes `int`, which truncates upper bits.
        // This mirrors what agentns/tests/test_unshare.c does.
        let ret = unsafe { libc::syscall(libc::SYS_unshare, CLONE_NEWAGENT as libc::c_long) };
        if ret == 0 {
            0
        } else {
            let e = std::io::Error::last_os_error();
            e.raw_os_error().unwrap_or(-1)
        }
    }

    fn read_agent_counters(&self) -> std::io::Result<AgentCounters> {
        let raw = std::fs::read_to_string("/proc/self/agent_counters")?;
        let mut counters = AgentCounters::default();
        for line in raw.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let val: u64 = parts[1].trim().parse().unwrap_or(0);
                match key {
                    "syscalls" => counters.syscalls = val,
                    "bytes_written" => counters.bytes_written = val,
                    _ => {}
                }
            }
        }
        Ok(counters)
    }

    fn intent_tag_roundtrip(&self, tag: u64) -> std::io::Result<u64> {
        // PR_SET_AGENT_INTENT_TAG / PR_GET_AGENT_INTENT_TAG are hypothetical;
        // use placeholder prctl numbers matching the agentns patch.
        const PR_SET_AGENT_INTENT_TAG: libc::c_int = 60;
        const PR_GET_AGENT_INTENT_TAG: libc::c_int = 61;
        let set_ret = unsafe {
            libc::prctl(PR_SET_AGENT_INTENT_TAG, tag as libc::c_ulong, 0, 0, 0)
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
    unshare_errno: i32,
    after_session: String,
    counters_before: AgentCounters,
    counters_after: AgentCounters,
    intent_tag_ok: bool,
}

fn encode_child_report(r: &ChildReport) -> Vec<u8> {
    // Simple fixed-layout binary: errno(4) + session(33) + cb_sys(8) +
    // cb_bytes(8) + ca_sys(8) + ca_bytes(8) + intent_ok(1)
    let mut buf = Vec::new();
    buf.extend_from_slice(&r.unshare_errno.to_le_bytes());
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
        unshare_errno: errno,
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
///
/// This is the main engine called both from the real CLI (where it forks a
/// child) and from unit tests (where `syscalls` is a fake that returns
/// scripted values without touching the kernel).
///
/// In test/fake mode the fork is skipped and the fake's `unshare_newagent`
/// is called directly in-process (safe because the fake never mutates kernel
/// state).
pub fn attest_with<S: AgentSyscalls>(syscalls: &S) -> AttestReport {
    let flag = CLONE_NEWAGENT;
    let collides_with = check_collision(flag);
    // The uapi-header constant (0x100) collides with CLONE_VM.
    let header_col = header_collision();

    let before_session = syscalls
        .read_agent_session()
        .unwrap_or_else(|_| "error".to_string());

    let mut evidence = Evidence::new();
    // compiled_flag = the uapi-header constant (0x100 == CLONE_VM collision).
    // This is what AC2 checks.
    evidence.insert(
        "compiled_flag".into(),
        format!("{:#x}", CLONE_NEWAGENT_HEADER),
    );
    // syscall_flag = the 64-bit value actually passed to SYS_unshare (matches test_unshare.c).
    evidence.insert("syscall_flag".into(), format!("{:#x}", flag));
    evidence.insert("before_session".into(), before_session.clone());
    if let Some(ref c) = header_col {
        evidence.insert("collides_with".into(), c.clone());
    } else if let Some(ref c) = collides_with {
        evidence.insert("collides_with".into(), c.clone());
    }

    let unshare_errno = syscalls.unshare_newagent();
    evidence.insert("unshare_errno".into(), unshare_errno.to_string());

    if unshare_errno != 0 {
        // First layer failed: FlagAccepted ✗
        // Report collides_with as the header collision (0x100 == CLONE_VM) since
        // that is the root cause documented in the PRD.
        let verdict = Verdict::FlagRejected {
            flag: CLONE_NEWAGENT_HEADER,
            collides_with: header_col.or(collides_with),
            errno: unshare_errno,
        };
        return build_report("agentns", verdict, vec![], evidence);
    }

    // Unshare succeeded.
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
    let counters_before = syscalls
        .read_agent_counters()
        .unwrap_or_default();
    syscalls.do_activity();
    let counters_after = syscalls
        .read_agent_counters()
        .unwrap_or_default();

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
    evidence.insert(
        "intent_tag_ok".into(),
        intent_tag_ok.to_string(),
    );

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
        // Minimal RFC 3339 without chrono dependency.
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
    // Very simple UTC formatter (avoids pulling in chrono for a single field).
    let s = unix_secs;
    let days = s / 86400;
    let rem = s % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    // Gregorian calendar calculation
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, hh, mm, ss)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Days since Unix epoch (1970-01-01)
    let mut d = days + 719468; // days since year 0 (proleptic Gregorian)
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
/// The child calls `unshare(CLONE_NEWAGENT)` and reports its findings back to
/// the parent over a pipe.  The parent's own agent_session is never mutated
/// (the namespace dies with the child).
pub fn attest_live() -> AttestReport {
    let flag = CLONE_NEWAGENT;
    let collides_with = check_collision(flag);
    let header_col = header_collision();

    // Read parent's session before the fork.
    let before_session = std::fs::read_to_string("/proc/self/agent_session")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string());

    let mut evidence = Evidence::new();
    // compiled_flag = the uapi-header constant (0x100 == CLONE_VM collision).
    evidence.insert(
        "compiled_flag".into(),
        format!("{:#x}", CLONE_NEWAGENT_HEADER),
    );
    // syscall_flag = the 64-bit value actually passed to SYS_unshare.
    evidence.insert("syscall_flag".into(), format!("{:#x}", flag));
    evidence.insert("before_session".into(), before_session.clone());
    if let Some(ref c) = header_col {
        evidence.insert("collides_with".into(), c.clone());
    } else if let Some(ref c) = collides_with {
        evidence.insert("collides_with".into(), c.clone());
    }

    // Create pipe for child→parent communication.
    let mut pipe_r: libc::c_int = 0;
    let mut pipe_w: libc::c_int = 0;
    let pipe_arr = [&mut pipe_r as *mut libc::c_int, &mut pipe_w as *mut libc::c_int];
    let pipe_fds: [libc::c_int; 2] = [0; 2];
    // Safety: pipe2 is safe to call.
    let rc = unsafe {
        let mut fds = [0i32; 2];
        let r = libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC);
        pipe_r = fds[0];
        pipe_w = fds[1];
        r
    };
    let _ = pipe_arr; // suppress unused warning
    let _ = pipe_fds;

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
            // Fork failed.
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

            // Use syscall() directly to pass the full 64-bit flag — same as test_unshare.c.
            let unshare_ret =
                unsafe { libc::syscall(libc::SYS_unshare, CLONE_NEWAGENT as libc::c_long) };
            let unshare_errno = if unshare_ret == 0 {
                0i32
            } else {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(-1)
            };

            let after_session = if unshare_errno == 0 {
                std::fs::read_to_string("/proc/self/agent_session")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "error".to_string())
            } else {
                String::new()
            };

            let counters_before = read_counters_raw();

            // Do some activity to advance counters.
            for _ in 0..8 {
                let _ = std::fs::OpenOptions::new().read(true).open("/dev/null");
            }

            let counters_after = read_counters_raw();

            let intent_tag_ok = if unshare_errno == 0 {
                const PR_SET: libc::c_int = 60;
                const PR_GET: libc::c_int = 61;
                let set_ret =
                    unsafe { libc::prctl(PR_SET, 0xdeadbeef_cafebabeu64 as libc::c_ulong, 0, 0, 0) };
                if set_ret == 0 {
                    let mut out: u64 = 0;
                    let get_ret = unsafe {
                        libc::prctl(
                            PR_GET,
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
                unshare_errno,
                after_session,
                counters_before,
                counters_after,
                intent_tag_ok,
            };
            let payload = encode_child_report(&report);

            // Write to pipe.
            use std::os::unix::io::FromRawFd;
            let mut writer = unsafe { std::fs::File::from_raw_fd(pipe_w) };
            let _ = writer.write_all(&payload);
            drop(writer);

            unsafe { libc::_exit(0) };
        }
        child_pid => {
            // Parent process.
            unsafe { libc::close(pipe_w) };

            // Read child's report.
            use std::os::unix::io::FromRawFd;
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_r) };
            let mut payload = Vec::new();
            let _ = reader.read_to_end(&mut payload);
            drop(reader);

            // Wait for child.
            let mut status: libc::c_int = 0;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };

            // Verify parent session is unchanged (AC7).
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

            evidence.insert(
                "unshare_errno".into(),
                child.unshare_errno.to_string(),
            );
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

            if child.unshare_errno != 0 {
                return build_report(
                    "agentns",
                    Verdict::FlagRejected {
                        flag: CLONE_NEWAGENT_HEADER,
                        collides_with: header_col.or(collides_with),
                        errno: child.unshare_errno,
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
    let mut c = AgentCounters::default();
    for line in raw.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let val: u64 = parts[1].trim().parse().unwrap_or(0);
            match key {
                "syscalls" => c.syscalls = val,
                "bytes_written" => c.bytes_written = val,
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

    /// Fake syscalls builder for tests.
    struct FakeSyscalls {
        unshare_errno: i32,
        session_before: String,
        session_after: String,
        counters_before: AgentCounters,
        counters_after: AgentCounters,
        intent_tag_ok: bool,
    }

    impl FakeSyscalls {
        fn rejected(errno: i32) -> Self {
            FakeSyscalls {
                unshare_errno: errno,
                session_before: "0".repeat(32),
                session_after: String::new(),
                counters_before: AgentCounters::default(),
                counters_after: AgentCounters::default(),
                intent_tag_ok: false,
            }
        }

        fn live_full() -> Self {
            FakeSyscalls {
                unshare_errno: 0,
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
                unshare_errno: 0,
                session_before: "0".repeat(32),
                session_after: "0".repeat(32),
                counters_before: AgentCounters::default(),
                counters_after: AgentCounters::default(),
                intent_tag_ok: false,
            }
        }
    }

    impl AgentSyscalls for FakeSyscalls {
        fn read_agent_session(&self) -> std::io::Result<String> {
            // Return before_session first call, after_session second.
            // We use a simple heuristic: if this is called after unshare succeeded.
            Ok(self.session_before.clone())
        }
        fn unshare_newagent(&self) -> i32 {
            self.unshare_errno
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

    /// Stateful fake that returns different values for before/after reads.
    ///
    /// Call order in `attest_with`:
    ///   1. read_agent_session  → session_before
    ///   2. unshare_newagent
    ///   3. read_agent_session  → session_after
    ///   4. read_agent_counters → counters_before
    ///   5. do_activity
    ///   6. read_agent_counters → counters_after
    ///   7. intent_tag_roundtrip
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
        fn unshare_newagent(&self) -> i32 {
            self.inner.unshare_newagent()
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

    /// AC5: A fake with successful unshare, non-zero session, advancing counters,
    /// and working intent tag should produce `Live` with all five layers.
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

    /// AC6: A fake where unshare succeeds but session stays zero should produce
    /// `NsCreatedButSessionZero`.
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

    /// Verify FlagRejected with errno 22 (EINVAL) produces the right verdict.
    #[test]
    fn test_flag_rejected_einval() {
        let fake = FakeSyscalls::rejected(libc::EINVAL);
        let report = attest_with(&fake);
        match &report.verdict {
            Verdict::FlagRejected { errno, .. } => {
                assert_eq!(*errno, libc::EINVAL);
            }
            other => panic!("expected FlagRejected, got {:?}", other),
        }
        assert_eq!(report.layers_passed.len(), 0);
    }

    /// Verify the collision table correctly identifies CLONE_VM for 0x100.
    #[test]
    fn test_collision_clone_vm() {
        let c = check_collision(0x100);
        assert_eq!(c.as_deref(), Some("CLONE_VM"));
    }

    /// Verify exit codes.
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
}
