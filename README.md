# assay

The booted `7.0.10-arch1-5-wintermute` kernel reports `agent_session` as 32

## Overview

The booted `7.0.10-arch1-5-wintermute` kernel reports `agent_session` as 32
zeros for every process. Two existing visions read that surface and reach
opposite-but-both-wrong conclusions: `quicken` calls it `Inert`, `onramp`
proposes wrapping the Claude launch in `unshare(CLONE_NEWAGENT)`. Neither ever
**creates** an agent namespace, so neither can tell whether the cause is
"nothing wraps the launch" or "the kernel physically rejects the flag." A
30-second live run settles it: `unshare(CLONE_NEWAGENT)` returns **EINVAL** —
the namespace cannot be created at all. `assay-agentns` is the missing tool: a
read-only Rust CLI that *exercises the actual mechanism* in a throwaway child
and emits a structured verdict localizing the broken layer, so a futile fix
never ships and a real root cause stops recurring in self-review.


## Acceptance


1. `cargo build` and `cargo test` are green on rustc 1.85 in
   `~/wintermute/assay`; `main()`'s first line is `sigpipe::reset()`.
2. `assay agentns --json` on the **current booted kernel** emits a report with
   `verdict.FlagRejected`, `evidence.unshare_errno == 22` (EINVAL),
   `evidence.compiled_flag == "0x100"`, and
   `evidence.collides_with == "CLONE_VM"`. (This is the proof the vision
   claims; it must reproduce the live finding.)
3. `assay agentns` (human form) prints a layer ladder showing `FlagAccepted ✗`
   as the first failed layer and a one-line remediation pointer
   ("kernel rejects the flag — see PRD-agentns-clone-flag-fix; wrapping the
   launch will not help").
4. Exit code is non-zero on the current kernel and the code encodes the
   `FlagRejected` class.
5. A unit test injects a fake `AgentSyscalls` whose `unshare` succeeds and
   whose post-unshare session is non-zero with advancing counters, and asserts
   the verdict is `Live { session }` with all five `Layer`s passed — proving
   the tool will correctly report success once the kernel is fixed.
6. A unit test injects a fake whose `unshare` succeeds but whose session stays
   zero, and asserts `NsCreatedButSessionZero` (so the tool distinguishes the
   flag bug from a *different* future kernel bug).
7. The child process leaves no residue: an assertion (or documented manual
   check) that `/proc/self/agent_session` in the **parent** is unchanged after
   the run (the attestation is non-mutating).
8. `README.md` documents the layer ladder, the verdict table, and the exact
   live command + expected output from AC2.

## Install

```sh
cargo install --path .
```

## License

MIT © Joe Yen
