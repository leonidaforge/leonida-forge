//! The engine's type registry as a document.
//!
//! The table is compiled into this binary from the reading of build `e95020b2`
//! recorded in the research repository. Printing all 256 ids makes the
//! unregistered ones explicit instead of leaving them to be inferred.

use lforge_core::registry::{self, Variant};
use serde_json::{Value, json};

/// The build the table was read from.
pub const SOURCE_BUILD: &str = "e95020b2";

/// Schema of the registry document.
pub const REGISTRY_SCHEMA: &str = "leonida-forge.rpf9-type-registry/1";

/// Runs the command: one JSON document, or one line per id.
pub fn run(json_output: bool) -> Result<(), String> {
    let variants = [Variant::Path, Variant::Alternate, Variant::Hash];
    let mut ids = Vec::new();
    for id in 0..=u8::MAX {
        let mut entry = serde_json::Map::new();
        entry.insert("type".to_string(), json!(id));
        match registry::native_extension(id) {
            Some(native) => {
                entry.insert("registered".to_string(), json!(true));
                entry.insert("extension".to_string(), json!(native.extension));
                entry.insert("variant".to_string(), json!(native.variant.name()));
                let aliases: Vec<Value> = variants
                    .iter()
                    .filter_map(|variant| registry::extension(id, *variant))
                    .map(|native| json!(native.extension))
                    .collect();
                entry.insert("variants".to_string(), Value::Array(aliases));
            }
            None => {
                entry.insert("registered".to_string(), json!(false));
                entry.insert("extension".to_string(), Value::Null);
                entry.insert("variants".to_string(), Value::Array(Vec::new()));
            }
        }
        ids.push(Value::Object(entry));
    }
    let registered = ids
        .iter()
        .filter(|entry| entry["registered"] == json!(true))
        .count();
    let document = json!({
        "schema": REGISTRY_SCHEMA,
        "source_build": SOURCE_BUILD,
        "unregistered_ids": u8::MAX as usize + 1 - registered,
        "registered_ids": registered,
        "ids": ids,
    });
    if json_output {
        let text = serde_json::to_string_pretty(&document).map_err(|err| err.to_string())?;
        println!("{text}");
    } else {
        println!("registered ids: {registered}");
        for entry in document["ids"].as_array().into_iter().flatten() {
            if entry["registered"] == json!(true) {
                println!(
                    "{:3}  {:<8} {}",
                    entry["type"], entry["extension"], entry["variants"]
                );
            }
        }
    }
    Ok(())
}
