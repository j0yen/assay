//! assay — probe and attest kernel subsystem support.
//!
//! Usage:
//!   assay agentns           # human-readable report
//!   assay agentns --json    # JSON AttestReport

use assay_core::agentns::attest_live;
use assay_core::types::{Layer, Verdict};

fn main() {
    sigpipe::reset();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: assay <subcommand> [--json]");
        eprintln!("Subcommands: agentns");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "agentns" => {
            let json_mode = args.iter().any(|a| a == "--json");
            cmd_agentns(json_mode);
        }
        other => {
            eprintln!("Unknown subcommand: {}", other);
            std::process::exit(1);
        }
    }
}

fn cmd_agentns(json_mode: bool) {
    let report = attest_live();
    let exit_code = report.verdict.exit_code();

    if json_mode {
        let json = serde_json::to_string_pretty(&report).expect("serialize failed");
        println!("{}", json);
    } else {
        // Human report
        println!("assay agentns — kernel: {}", report.kernel_release);
        println!("checked: {}", report.checked_at);
        println!();

        // Verdict line
        match &report.verdict {
            Verdict::FlagRejected {
                flag,
                collides_with,
                errno,
            } => {
                println!("VERDICT: FlagRejected");
                println!(
                    "  compiled_flag = {:#010x}",
                    flag
                );
                if let Some(c) = collides_with {
                    println!("  collides_with = {}", c);
                }
                println!("  unshare errno  = {} (EINVAL=22)", errno);
            }
            Verdict::NsCreatedButSessionZero => {
                println!("VERDICT: NsCreatedButSessionZero");
            }
            Verdict::CountersDead => {
                println!("VERDICT: CountersDead");
            }
            Verdict::IntentTagLost => {
                println!("VERDICT: IntentTagLost");
            }
            Verdict::Live { session } => {
                println!("VERDICT: Live  session={}", session);
            }
            Verdict::Unknown { detail } => {
                println!("VERDICT: Unknown  detail={}", detail);
            }
        }
        println!();

        // Layer ladder
        let all_layers = [
            Layer::FlagAccepted,
            Layer::NsCreated,
            Layer::SessionNonZero,
            Layer::CountersAdvance,
            Layer::IntentTagRoundtrip,
        ];
        println!("Layer ladder:");
        // Find the first failed layer.
        let first_failed = first_failed_layer(&report.verdict);
        for layer in &all_layers {
            let passed = report.layers_passed.contains(layer);
            let marker = if passed { "✓" } else { "✗" };
            let suffix = if Some(layer) == first_failed.as_ref() {
                " ← first failure"
            } else {
                ""
            };
            println!("  {} {}{}", marker, layer.name(), suffix);
        }
        println!();
        println!("Remediation: {}", report.verdict.remediation());
        println!();

        // Decisive evidence
        println!("Evidence:");
        for (k, v) in &report.evidence {
            println!("  {}: {}", k, v);
        }
    }

    std::process::exit(exit_code);
}

fn first_failed_layer(verdict: &Verdict) -> Option<Layer> {
    match verdict {
        Verdict::FlagRejected { .. } => Some(Layer::FlagAccepted),
        Verdict::NsCreatedButSessionZero => Some(Layer::SessionNonZero),
        Verdict::CountersDead => Some(Layer::CountersAdvance),
        Verdict::IntentTagLost => Some(Layer::IntentTagRoundtrip),
        Verdict::Live { .. } => None,
        Verdict::Unknown { .. } => None,
    }
}

// Compile-time assertion: CLONE_NEWAGENT_HEADER must equal 0x100 (CLONE_VM collision).
use assay_core::agentns::CLONE_NEWAGENT_HEADER;
const _: () = {
    assert!(CLONE_NEWAGENT_HEADER == 0x100, "CLONE_NEWAGENT_HEADER constant mismatch");
};
