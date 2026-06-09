# assay

A Rust CLI that probes and attests kernel subsystem support. The first
subcommand (`assay agentns`) exercises the kernel agentns mechanism in a
throwaway child process and emits a structured verdict.

## Layer ladder

The agentns attestation walks five layers in order and stops at the first failure:

| Layer               | What it checks                                              |
|---------------------|-------------------------------------------------------------|
| `FlagAccepted`      | `unshare(CLONE_NEWAGENT)` returns 0 (no EINVAL)            |
| `NsCreated`         | Namespace was created (implied by FlagAccepted success)    |
| `SessionNonZero`    | `/proc/self/agent_session` is non-zero after namespace     |
| `CountersAdvance`   | `/proc/self/agent_counters` advances after syscall activity|
| `IntentTagRoundtrip`| `prctl(PR_SET/GET_AGENT_INTENT_TAG)` roundtrip succeeds    |

## Verdict table

| Verdict                    | Exit code | Meaning                                                  |
|----------------------------|-----------|----------------------------------------------------------|
| `Live`                     | 0         | All layers passed — mechanism fully functional           |
| `FlagRejected`             | 1         | `unshare` failed; flag is bad (collision or unimplemented)|
| `NsCreatedButSessionZero`  | 2         | Namespace created but session ID stayed zero             |
| `CountersDead`             | 3         | Namespace + session OK but counters never advance        |
| `IntentTagLost`            | 4         | Intent tag not preserved through prctl roundtrip         |
| `Unknown`                  | 5         | Unexpected error; see evidence                           |

## Live run on the current kernel (7.0.10-arch1-5-wintermute)

```
$ assay agentns --json
{
  "primitive": "agentns",
  "verdict": {
    "type": "FlagRejected",
    "detail": {
      "flag": 256,
      "collides_with": "CLONE_VM",
      "errno": 22
    }
  },
  "layers_passed": [],
  "evidence": {
    "before_session": "00000000000000000000000000000000",
    "collides_with": "CLONE_VM",
    "compiled_flag": "0x00000100",
    "unshare_errno": "22",
    ...
  },
  "kernel_release": "7.0.10-arch1-5-wintermute",
  "checked_at": "..."
}
```

Key fields: `verdict.FlagRejected`, `evidence.unshare_errno == 22` (EINVAL),
`evidence.compiled_flag == "0x00000100"`, `evidence.collides_with == "CLONE_VM"`.

**Root cause:** `CLONE_NEWAGENT` is defined as `0x100` in the agentns uapi header,
which collides with `CLONE_VM`. The legacy clone-flag space is exhausted. The
fix is to move the flag to an unused bit (e.g. via a prctl-based approach).
See `PRD-agentns-clone-flag-fix` for the remediation path.
Wrapping the launch in `unshare(CLONE_NEWAGENT)` will not help until this is fixed.

## Usage

```sh
# Human-readable report
assay agentns

# JSON report (stable shape for consumers)
assay agentns --json
```
