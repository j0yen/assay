# assay

A read-only CLI that exercises the kernel's agent-namespace mechanism in a throwaway child process and emits a structured verdict localizing the layer that fails.

## Why it exists

When a primitive is broken, the cheapest mistake is fixing the wrong layer. `/proc/self/agent_session` reading as all-zeros can mean several different things — the kernel doesn't have the feature, the syscall is rejected for lack of privilege, the namespace is created but the session ID never gets assigned, the counters never advance — and from the symptom alone you can't tell which. A fix aimed at the wrong layer ships, doesn't work, and the question reopens.

`assay` settles it by running the actual mechanism rather than reasoning about it. It forks a child, has the child attempt to create and enter an agent namespace, then walks five layers in order and reports the first one that fails. The output is a verdict with an exit code and the raw evidence behind it, so the fix can target the layer that's actually broken.

The attestation is non-mutating: the namespace lives and dies in the child, and the parent's `agent_session` is unchanged after the run (the report carries `parent_session_unchanged` as proof).

## How the namespace is created

Creation goes through `prctl(PR_SET_AGENT_NS)`, not `unshare()`. The 32-bit clone-flag space is exhausted — the bit that would have been `CLONE_NEWAGENT` (`0x100`) is already `CLONE_VM` — so there is no free clone flag to hang a new namespace off. `prctl` has a separate dispatch table with room. The agent prctl operations dispatch off `PR_AGENT_BASE = 0x41544E53` (the ASCII "ATNS"); `PR_SET_AGENT_NS` is base + 7 = `0x41544E5A`, and requires `CAP_SYS_ADMIN`.

## Install

```sh
cargo install --path .
```

Builds on Rust 1.85. `main()`'s first statement is `sigpipe::reset()`, so piping the output into `head` never panics.

## Quick start

```sh
assay agentns          # human-readable report
assay agentns --json   # machine-readable AttestReport
```

On a kernel without the agentns patch, the prctl is rejected and you get:

```
assay agentns — kernel: 6.17.0-35-generic

VERDICT: PrctlRejected
  prctl_op      = 0x41544e5a (PR_SET_AGENT_NS)
  errno         = 22 (EINVAL — kernel does not know PR_SET_AGENT_NS (wrong kernel?))

Layer ladder:
  ✗ FlagAccepted ← first failure
  ✗ NsCreated
  ✗ SessionNonZero
  ✗ CountersAdvance
  ✗ IntentTagRoundtrip

Remediation: prctl(PR_SET_AGENT_NS) rejected — ensure linux-wintermute kernel is booted and caller has CAP_SYS_ADMIN (try: sudo assay agentns)
```

`EINVAL` here means the kernel does not recognize the prctl op at all — the agentns kernel is not booted. `EPERM` would mean the op exists but the caller lacks `CAP_SYS_ADMIN` (retry under `sudo`).

## The layer ladder

The attestation walks five layers in order; the verdict names the first that fails.

| Layer | What it checks |
|---|---|
| `FlagAccepted` | `prctl(PR_SET_AGENT_NS)` returns success |
| `NsCreated` | a fresh agent namespace was entered |
| `SessionNonZero` | after creation, `agent_session` is no longer all-zeros |
| `CountersAdvance` | `agent_counters` move after some syscall activity in the namespace |
| `IntentTagRoundtrip` | an intent tag set via prctl reads back unchanged |

## Verdicts and exit codes

The exit code encodes the verdict class, so a script can branch on health without parsing the human output.

| Verdict | Exit | Meaning |
|---|---|---|
| `Live { session }` | `0` | all five layers passed; the mechanism works |
| `FlagRejected { errno }` | `1` | prctl rejected — wrong kernel (`EINVAL`) or no privilege (`EPERM`) |
| `NsCreatedButSessionZero` | `2` | flag accepted but session stayed zero — session-id assignment broken |
| `CountersDead` | `3` | namespace and session set, but counters never moved — accounting hook missing |
| `IntentTagLost` | `4` | intent tag not preserved through the prctl roundtrip |
| `Unknown { detail }` | `5` | `pipe()`/`fork()` failed or the child report didn't decode |

Each verdict carries a one-line remediation pointer in the human report.

## Layout

- `assay` — the binary; argument parsing and the human/JSON renderers (`src/main.rs`).
- `assay-core` — the types (`Verdict`, `Layer`, `AttestReport`) and the attestation logic. The syscall surface sits behind the `AgentSyscalls` trait, so the layer-walking logic is unit-tested against scripted fakes without needing a special kernel; `attest_live()` is the forking implementation the CLI uses.

## License

MIT © Joe Yen
