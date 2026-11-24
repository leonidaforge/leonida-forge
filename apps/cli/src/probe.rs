//! `lforge archive probe`: the bounded A-table compatibility probe.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use lforge_binary::pe::ExecutableView;
use lforge_rage9::rpf::metadata::probe::{
    AUTHENTICATION, DescriptorInfo, ProbeError, ProbeOutcome, ProbeReport, probe,
};
use lforge_rage9::rpf::metadata::verify::{
    SignatureOutcome, VerifyOutcome, VerifyReport, verify_archive,
};
use serde_json::{Value, json};

pub fn run(archive: &Path, executable: &Path, json_output: bool) -> Result<(), String> {
    let mut source = lforge_binary::Source::open(archive)
        .map_err(|err| format!("cannot open the archive: {err}"))?;
    let view = match ExecutableView::open(executable) {
        Ok(view) => view,
        Err(_) => {
            let report = failed_json(
                "executable_unsupported",
                "the executable is not supported",
                false,
            );
            print_json(&report, json_output);
            return Err("the executable is not a supported PE32+ image".into());
        }
    };

    let cancel = AtomicBool::new(false);
    let report = match probe(&mut source, &view, &cancel) {
        Ok(report) => report,
        Err(error) => {
            let (outcome, reason) = match error {
                ProbeError::Archive(reason) => ("archive_unsupported", reason),
                ProbeError::Read(reason) => ("read_failed", reason),
            };
            let report = failed_json(outcome, reason, true);
            print_json(&report, json_output);
            return Err(error.to_string());
        }
    };

    let verification = verify_archive(&mut source, &view, &cancel).ok();
    let value = report_json(&report, verification.as_ref());
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON value")
        );
    } else {
        print_text(&report, verification.as_ref());
    }
    if report.outcome.is_plausible() || report.outcome.is_not_applicable() {
        Ok(())
    } else {
        Err(format!("the probe did not pass: {}", report.outcome))
    }
}

fn print_json(value: &Value, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(value).expect("JSON value")
        );
    }
}

fn failed_json(outcome: &str, reason: &str, executable_ok: bool) -> Value {
    let executable = if executable_ok {
        json!({"status": "ok"})
    } else {
        json!({"status": "failed", "reason": reason})
    };
    json!({
        "format": "RPF9",
        "probe": {
            "outcome": outcome,
            "reason": reason,
            "authentication": AUTHENTICATION,
            "archive": Value::Null,
            "stages": {
                "executable": executable,
                "registry": {"status": "not_attempted"},
                "descriptor": {"status": "not_attempted"},
                "state": {"status": "not_attempted"},
                "fixed_tables": {"status": "not_attempted"},
                "block": {"status": "not_attempted"},
                "a_table": {"status": "not_attempted"},
                "signature": {"status": "not_attempted"},
                "archive": {"status": "not_attempted"},
            },
            "trust": {"status": "not_attempted"},
        },
    })
}

fn outcome_name(outcome: &ProbeOutcome) -> &'static str {
    match outcome {
        ProbeOutcome::NotApplicable => "not_applicable",
        ProbeOutcome::ArchiveUnsupported(_) => "archive_unsupported",
        ProbeOutcome::RegistryUnsupported(_) => "registry_unsupported",
        ProbeOutcome::DescriptorUnsupported(_) => "descriptor_unsupported",
        ProbeOutcome::StateUnsupported(_) => "state_unsupported",
        ProbeOutcome::FixedTablesUnsupported(_) => "fixed_tables_unsupported",
        ProbeOutcome::BlockUnsupported(_) => "block_unsupported",
        ProbeOutcome::Implausible(_) => "a_table_implausible",
        ProbeOutcome::Plausible => "a_table_plausible",
        ProbeOutcome::Cancelled => "cancelled",
        ProbeOutcome::ResourceLimit { .. } => "resource_limit",
    }
}

fn outcome_reason(outcome: &ProbeOutcome) -> String {
    match outcome {
        ProbeOutcome::NotApplicable => "the header selects no static pass".into(),
        ProbeOutcome::Plausible => "the decrypted A table is structurally plausible".into(),
        ProbeOutcome::ArchiveUnsupported(reason)
        | ProbeOutcome::RegistryUnsupported(reason)
        | ProbeOutcome::DescriptorUnsupported(reason)
        | ProbeOutcome::StateUnsupported(reason)
        | ProbeOutcome::FixedTablesUnsupported(reason)
        | ProbeOutcome::BlockUnsupported(reason)
        | ProbeOutcome::Implausible(reason) => (*reason).into(),
        ProbeOutcome::Cancelled => "the probe was cancelled".into(),
        ProbeOutcome::ResourceLimit { what, limit } => {
            format!("the {what} exceeds the limit of {limit}")
        }
    }
}

fn report_json(report: &ProbeReport, verification: Option<&VerifyReport>) -> Value {
    json!({
        "format": "RPF9",
        "probe": {
            "outcome": outcome_name(&report.outcome),
            "reason": outcome_reason(&report.outcome),
            "authentication": AUTHENTICATION,
            "archive": {
                "selector": report.selector,
                "static_pass": report.static_pass,
                "a_records": report.a_records,
                "b_size": report.b_size,
            },
            "stages": {
                "executable": {"status": "ok"},
                "registry": registry_stage(report),
                "descriptor": descriptor_stage(report),
                "state": simple_stage(report, Stage::State, report.state_identified),
                "fixed_tables": fixed_tables_stage(report),
                "block": simple_stage(report, Stage::Block, report.block_initialized),
                "a_table": a_table_stage(report),
                "signature": signature_stage(verification),
                "archive": archive_stage(verification),
            },
            "trust": trust_stage(verification),
        },
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Registry,
    Descriptor,
    State,
    FixedTables,
    Block,
    ATable,
}

impl Stage {
    fn failed_by(self, outcome: &ProbeOutcome) -> bool {
        matches!(
            (self, outcome),
            (Stage::Registry, ProbeOutcome::RegistryUnsupported(_))
                | (Stage::Descriptor, ProbeOutcome::DescriptorUnsupported(_))
                | (Stage::State, ProbeOutcome::StateUnsupported(_))
                | (Stage::FixedTables, ProbeOutcome::FixedTablesUnsupported(_))
                | (Stage::Block, ProbeOutcome::BlockUnsupported(_))
                | (Stage::ATable, ProbeOutcome::Implausible(_))
                | (Stage::ATable, ProbeOutcome::ArchiveUnsupported(_))
        )
    }

    fn complete(self, report: &ProbeReport) -> bool {
        match self {
            Stage::Registry => report.registry_records.is_some(),
            Stage::Descriptor => report.descriptor.is_some(),
            Stage::State => report.state_identified,
            Stage::FixedTables => report.fixed_tables,
            Stage::Block => report.block_initialized,
            Stage::ATable => report.a_table.is_some(),
        }
    }
}

fn first_incomplete(report: &ProbeReport) -> Option<Stage> {
    [
        Stage::Registry,
        Stage::Descriptor,
        Stage::State,
        Stage::FixedTables,
        Stage::Block,
        Stage::ATable,
    ]
    .into_iter()
    .find(|stage| !stage.complete(report))
}

fn simple_stage(report: &ProbeReport, stage: Stage, complete: bool) -> Value {
    if complete {
        return json!({"status": "ok"});
    }
    if stage.failed_by(&report.outcome) {
        return json!({"status": "failed", "reason": outcome_reason(&report.outcome)});
    }
    stopped_or_skipped(report, stage)
}

fn fixed_tables_stage(report: &ProbeReport) -> Value {
    if report.fixed_tables {
        return json!({
            "status": "ok",
            "candidates": report.fixed_tables_candidates,
        });
    }
    if Stage::FixedTables.failed_by(&report.outcome) {
        return json!({"status": "failed", "reason": outcome_reason(&report.outcome)});
    }
    stopped_or_skipped(report, Stage::FixedTables)
}

fn stopped_or_skipped(report: &ProbeReport, stage: Stage) -> Value {
    if matches!(
        report.outcome,
        ProbeOutcome::Cancelled | ProbeOutcome::ResourceLimit { .. }
    ) && first_incomplete(report) == Some(stage)
    {
        return json!({"status": "stopped", "reason": outcome_reason(&report.outcome)});
    }
    json!({"status": "not_attempted"})
}

fn registry_stage(report: &ProbeReport) -> Value {
    match report.registry_records {
        Some(records) => json!({
            "status": "ok",
            "records": records,
            "algorithm_states": report.registry_algorithm_states.unwrap_or(0),
        }),
        None => {
            if Stage::Registry.failed_by(&report.outcome) {
                json!({"status": "failed", "reason": outcome_reason(&report.outcome)})
            } else {
                stopped_or_skipped(report, Stage::Registry)
            }
        }
    }
}

fn descriptor_stage(report: &ProbeReport) -> Value {
    match report.descriptor {
        Some(DescriptorInfo {
            index,
            kind,
            algorithm_id,
            provider,
        }) => json!({
            "status": "ok",
            "index": index,
            "kind": kind,
            "algorithm": algorithm_id,
            "provider": provider,
        }),
        None => {
            if Stage::Descriptor.failed_by(&report.outcome) {
                json!({"status": "failed", "reason": outcome_reason(&report.outcome)})
            } else {
                stopped_or_skipped(report, Stage::Descriptor)
            }
        }
    }
}

fn a_table_stage(report: &ProbeReport) -> Value {
    match report.a_table {
        Some(summary) => json!({
            "status": "ok",
            "records": summary.records,
            "known_ids": summary.known_ids,
            "candidate": report.selected_fixed_table,
        }),
        None => {
            if Stage::ATable.failed_by(&report.outcome) {
                json!({"status": "failed", "reason": outcome_reason(&report.outcome)})
            } else {
                stopped_or_skipped(report, Stage::ATable)
            }
        }
    }
}

fn signature_stage(report: Option<&VerifyReport>) -> Value {
    let Some(report) = report else {
        return json!({"status": "not_attempted"});
    };
    match &report.signature {
        SignatureOutcome::Valid => json!({"status": "ok", "result": "valid"}),
        SignatureOutcome::Invalid => json!({
            "status": "failed",
            "result": "invalid",
            "reason": "the signature does not match the metadata",
        }),
        SignatureOutcome::Unavailable(reason) => json!({
            "status": "unavailable",
            "result": "unavailable",
            "reason": reason,
        }),
        SignatureOutcome::Unsupported(reason) => json!({
            "status": "unsupported",
            "result": "unsupported",
            "reason": reason,
        }),
        SignatureOutcome::NotPerformed => json!({"status": "not_attempted"}),
    }
}

fn archive_stage(report: Option<&VerifyReport>) -> Value {
    let Some(report) = report else {
        return json!({"status": "not_attempted"});
    };
    match report.archive_pass {
        Some(true) => json!({"status": "ok", "pass": true}),
        Some(false) => json!({"status": "skipped", "pass": false}),
        None => json!({"status": "not_attempted"}),
    }
}

fn trust_stage(report: Option<&VerifyReport>) -> Value {
    let Some(report) = report else {
        return json!({"status": "unavailable"});
    };
    let status = match report.outcome {
        VerifyOutcome::MetadataDecodedAuthenticated => "authenticated",
        VerifyOutcome::MetadataDecodedUnverified => "unverified",
        VerifyOutcome::SignatureInvalid => "invalid",
        VerifyOutcome::NotApplicable => "not_applicable",
        VerifyOutcome::Cancelled | VerifyOutcome::ResourceLimit { .. } => "stopped",
        _ => "failed",
    };
    json!({
        "status": status,
        "outcome": report.outcome.to_string(),
        "stage": report.stage,
    })
}

fn print_text(report: &ProbeReport, verification: Option<&VerifyReport>) {
    println!("format:       RPF9");
    println!("selector:     {:#04x}", report.selector);
    println!(
        "static pass:  {}",
        if report.static_pass { "yes" } else { "no" }
    );
    println!("A records:    {}", report.a_records);
    println!("B size:       {} bytes", report.b_size);
    if let Some(records) = report.registry_records {
        println!(
            "registry:     {records} records, {} algorithm-0x10 states",
            report.registry_algorithm_states.unwrap_or(0)
        );
    }
    if let Some(descriptor) = report.descriptor {
        println!(
            "descriptor:   index {}, cipher type {:#x}, algorithm {:#x}, provider {}",
            descriptor.index, descriptor.kind, descriptor.algorithm_id, descriptor.provider
        );
    }
    if report.state_identified {
        println!("state:        identified");
    }
    if report.fixed_tables {
        println!(
            "fixed tables: {} structurally valid candidate(s)",
            report.fixed_tables_candidates
        );
    }
    if report.block_initialized {
        println!("block:        initialized");
    }
    if let Some(summary) = report.a_table {
        let candidate = report
            .selected_fixed_table
            .map(|index| format!(", candidate {index}"))
            .unwrap_or_default();
        println!(
            "A table:      plausible ({} records, {} known sub-blocks{candidate})",
            summary.records, summary.known_ids
        );
    }
    if let Some(verification) = verification {
        println!("signature:    {}", verification.signature);
        println!(
            "trust:        {} (stage {})",
            verification.outcome, verification.stage
        );
    }
    println!("authentication: {AUTHENTICATION}");
    println!();
    println!("result:       {}", report.outcome);
    match &report.outcome {
        ProbeOutcome::Plausible => {
            println!(
                "The decrypted A table is structural evidence only. It is not a signature check."
            );
        }
        ProbeOutcome::NotApplicable => {
            println!("This archive needs no static pass, so the probe does not apply.");
        }
        _ => {
            println!("A failed probe is not proof of a wrong key.");
        }
    }
}
