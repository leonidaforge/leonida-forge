//! `lforge catalog validate`.
//!
//! The package is untrusted input. The validator reads the central directory
//! through the bounded ZIP reader, copies only declared entries into bounded
//! buffers, verifies every size and SHA-256, scans JSON for duplicate keys and
//! checks the catalog records and relationships. It never extracts an entry to
//! the filesystem.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::Read;
use std::sync::atomic::AtomicBool;

#[cfg(test)]
mod tests;

use lforge_core::zip;
use serde_json::{Map, Value, json};

use crate::catalog::json::{
    duplicate_key, iso_timestamp, package_id, record_id, safe_path, sha256_hex, sha256_is_hex,
};

pub const MANIFEST_VERSION: &str = "1.1.0";
pub const LEGACY_MANIFEST_VERSION: &str = "1.0.0";
pub const CATALOG_SCHEMA_VERSION: &str = "1";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const CHECKSUMS_FILE: &str = "checksums.json";

const CATEGORIES: [&str; 4] = ["peds", "weapons", "vehicles", "clothing"];
const CATALOG_FILES: [(&str, &str); 5] = [
    ("data/peds.ndjson", "leonidaforge.catalog.peds/1"),
    ("data/weapons.ndjson", "leonidaforge.catalog.weapons/1"),
    ("data/vehicles.ndjson", "leonidaforge.catalog.vehicles/1"),
    ("data/clothing.ndjson", "leonidaforge.catalog.clothing/1"),
    (
        "data/relationships.ndjson",
        "leonidaforge.catalog.relationships/1",
    ),
];
const RECORD_SCHEMA: &str = "leonidaforge.catalog.record/1";
const RELATIONSHIP_SCHEMA: &str = "leonidaforge.catalog.relationship/1";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_CHECKSUMS_BYTES: u64 = 256 * 1024;
const MAX_REPORTED_ISSUES: usize = 100;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_MEDIA_ID: usize = 128;

pub struct Options {
    pub package: std::path::PathBuf,
    pub json: bool,
    pub max_package_bytes: u64,
    pub max_total_bytes: u64,
    pub max_data_file_bytes: u64,
    pub max_image_bytes: u64,
    pub max_entries: u64,
    pub max_compression_ratio: u64,
    pub max_records: u64,
}

#[derive(Default)]
struct Issues {
    items: Vec<Value>,
    count: u64,
}

impl Issues {
    fn add(&mut self, code: &str, message: impl Into<String>, path: Option<&str>) {
        self.count += 1;
        if self.items.len() < MAX_REPORTED_ISSUES {
            let mut value = json!({ "code": code, "message": message.into() });
            if let Some(path) = path {
                value["path"] = json!(path);
            }
            self.items.push(value);
        }
    }
}

struct Declared {
    path: String,
    schema_id: String,
    size: u64,
    sha256: String,
}

struct ImageDeclared {
    path: String,
    format: String,
    size: u64,
    sha256: String,
    width: u64,
    height: u64,
}

#[allow(dead_code)]
struct Manifest {
    package_id: String,
    manifest_version: String,
    catalog_schema_version: String,
    created_at: String,
    exporter_name: String,
    exporter_version: String,
    forge_version: String,
    forge_revision: Option<String>,
    game_build: String,
    game_build_source: Option<String>,
    scope_kind: String,
    categories: Vec<String>,
    counts: BTreeMap<String, u64>,
    limitations: Vec<String>,
    data: Vec<Declared>,
    images: Vec<ImageDeclared>,
}

pub fn run(options: Options) -> Result<(), String> {
    let size = std::fs::metadata(&options.package)
        .map_err(|err| format!("cannot read {}: {err}", options.package.display()))?
        .len();
    let mut issues = Issues::default();
    if size > options.max_package_bytes {
        issues.add(
            "package_too_large",
            format!(
                "the ZIP is {size} bytes, above the {} byte limit",
                options.max_package_bytes
            ),
            None,
        );
        return finish(&options, None, None, issues);
    }

    let mut file = File::open(&options.package)
        .map_err(|err| format!("cannot open {}: {err}", options.package.display()))?;
    let cancel = AtomicBool::new(false);
    let archive = match zip::Archive::read(
        &mut file,
        &zip::Limits {
            max_entries: options.max_entries,
            max_metadata: 64 * 1024 * 1024,
        },
        &cancel,
    ) {
        Ok(archive) => archive,
        Err(err) => {
            issues.add("invalid_zip", err.to_string(), None);
            return finish(&options, None, None, issues);
        }
    };
    let package_sha256 = sha256_file(&mut file)?;

    // Inventory, paths and duplicates.
    let mut names = BTreeSet::new();
    let mut lowered = HashSet::new();
    let mut total_declared = 0u64;
    for entry in &archive.entries {
        total_declared = total_declared.saturating_add(entry.uncompressed_size);
        if !safe_path(&entry.name) {
            issues.add(
                "unsafe_path",
                "the entry path is not a safe relative path",
                Some(&entry.name),
            );
            continue;
        }
        if !names.insert(entry.name.clone()) {
            issues.add(
                "duplicate_path",
                "two ZIP entries share a path",
                Some(&entry.name),
            );
        }
        if !lowered.insert(entry.name.to_lowercase()) {
            issues.add(
                "duplicate_path_case",
                "two ZIP entries differ only by case",
                Some(&entry.name),
            );
        }
        if entry.is_dir() {
            issues.add(
                "directory_entry",
                "the package contains a directory entry",
                Some(&entry.name),
            );
        }
        if entry.is_encrypted() {
            issues.add(
                "encrypted_entry",
                "encrypted entries are not accepted",
                Some(&entry.name),
            );
        }
        if !entry.compression.is_supported() {
            issues.add(
                "unsupported_compression",
                "only stored and deflated entries are accepted",
                Some(&entry.name),
            );
        }
        let allowed = entry.name == MANIFEST_FILE
            || entry.name == CHECKSUMS_FILE
            || entry.name.starts_with("data/")
            || entry.name.starts_with("images/");
        if !allowed {
            issues.add(
                "unexpected_entry",
                "the entry is outside the allowed layout",
                Some(&entry.name),
            );
        }
        if entry.uncompressed_size > 256 * 1024
            && entry.compressed_size > 0
            && entry.uncompressed_size / entry.compressed_size > options.max_compression_ratio
        {
            issues.add(
                "compression_ratio",
                "the entry exceeds the compression ratio limit",
                Some(&entry.name),
            );
        }
    }
    if total_declared > options.max_total_bytes {
        issues.add(
            "total_size",
            format!(
                "the declared uncompressed total is {total_declared} bytes, above the {} byte limit",
                options.max_total_bytes
            ),
            None,
        );
    }

    let manifest_bytes = match read_named(
        &archive,
        &mut file,
        MANIFEST_FILE,
        MAX_MANIFEST_BYTES,
        &cancel,
        &mut issues,
    ) {
        Some(bytes) => bytes,
        None => return finish(&options, Some(&archive), Some(package_sha256), issues),
    };
    let checksums_bytes = match read_named(
        &archive,
        &mut file,
        CHECKSUMS_FILE,
        MAX_CHECKSUMS_BYTES,
        &cancel,
        &mut issues,
    ) {
        Some(bytes) => bytes,
        None => return finish(&options, Some(&archive), Some(package_sha256), issues),
    };

    let manifest_value = match parse_json(&manifest_bytes, MANIFEST_FILE, &mut issues) {
        Some(value) => value,
        None => return finish(&options, Some(&archive), Some(package_sha256), issues),
    };
    let checksums_value = match parse_json(&checksums_bytes, CHECKSUMS_FILE, &mut issues) {
        Some(value) => value,
        None => return finish(&options, Some(&archive), Some(package_sha256), issues),
    };

    let manifest = match read_manifest(&manifest_value, &mut issues) {
        Some(manifest) => manifest,
        None => return finish(&options, Some(&archive), Some(package_sha256), issues),
    };

    let legacy = manifest.manifest_version == LEGACY_MANIFEST_VERSION;
    if !legacy && manifest.manifest_version != MANIFEST_VERSION {
        issues.add(
            "unsupported_manifest_version",
            format!(
                "only manifest versions {LEGACY_MANIFEST_VERSION} and {MANIFEST_VERSION} are supported"
            ),
            Some(MANIFEST_FILE),
        );
    }
    if legacy {
        if !manifest.data.is_empty() {
            issues.add(
                "unsupported_data_schema",
                "legacy packages declare no catalog data",
                Some(MANIFEST_FILE),
            );
        }
    } else if manifest.catalog_schema_version != CATALOG_SCHEMA_VERSION {
        issues.add(
            "unsupported_catalog_schema",
            format!("only catalog schema version {CATALOG_SCHEMA_VERSION} is supported"),
            Some(MANIFEST_FILE),
        );
    }
    if manifest.package_id != package_id_of(&manifest_value) {
        // Already checked while reading.
    }

    // Checksums file.
    let mut checksum_map: BTreeMap<String, (u64, String)> = BTreeMap::new();
    if let Some(checksums) = checksums_value.as_object() {
        if checksums.get("checksumsVersion").and_then(Value::as_str) != Some("1") {
            issues.add(
                "checksums_version",
                "checksumsVersion must be 1",
                Some(CHECKSUMS_FILE),
            );
        }
        if checksums.get("packageId").and_then(Value::as_str) != Some(manifest.package_id.as_str())
        {
            issues.add(
                "package_id_mismatch",
                "the manifest and checksums file name different packages",
                Some(CHECKSUMS_FILE),
            );
        }
        match checksums.get("files").and_then(Value::as_object) {
            Some(files) => {
                for (path, value) in files {
                    if !safe_path(path) {
                        issues.add(
                            "unsafe_checksum_path",
                            "a checksums path is unsafe",
                            Some(path),
                        );
                        continue;
                    }
                    let size = value.get("sizeBytes").and_then(Value::as_u64);
                    let sha = value.get("sha256").and_then(Value::as_str);
                    match (size, sha) {
                        (Some(size), Some(sha)) if sha256_is_hex(sha) => {
                            checksum_map.insert(path.clone(), (size, sha.to_string()));
                        }
                        _ => issues.add(
                            "checksums_entry_invalid",
                            "a checksums entry is invalid",
                            Some(path),
                        ),
                    }
                }
            }
            None => issues.add(
                "checksums_files",
                "checksums.json has no files object",
                Some(CHECKSUMS_FILE),
            ),
        }
    } else {
        issues.add(
            "checksums_object",
            "checksums.json is not an object",
            Some(CHECKSUMS_FILE),
        );
    }
    if checksum_map.contains_key(CHECKSUMS_FILE) {
        issues.add(
            "checksums_self_reference",
            "checksums.json must not list itself",
            Some(CHECKSUMS_FILE),
        );
    }
    if !checksum_map.contains_key(MANIFEST_FILE) {
        issues.add(
            "checksums_missing_manifest",
            "checksums.json must cover manifest.json",
            Some(CHECKSUMS_FILE),
        );
    } else if let Some((size, sha)) = checksum_map.get(MANIFEST_FILE)
        && (*size != manifest_bytes.len() as u64 || *sha != sha256_hex(&manifest_bytes))
    {
        issues.add(
            "manifest_checksum_mismatch",
            "manifest.json does not match its checksums entry",
            Some(MANIFEST_FILE),
        );
    }

    let declared_paths = manifest
        .data
        .iter()
        .map(|entry| entry.path.clone())
        .chain(manifest.images.iter().map(|entry| entry.path.clone()))
        .collect::<BTreeSet<_>>();
    for declared in &declared_paths {
        if !names.contains(declared) {
            issues.add(
                "missing_declared_file",
                "a declared file is not in the archive",
                Some(declared),
            );
        }
        match checksum_map.get(declared) {
            Some((size, _)) if declared_entry_size(&manifest, declared) == Some(*size) => {}
            Some(_) => issues.add(
                "declared_size_mismatch",
                "the declarations disagree about a size",
                Some(declared),
            ),
            None => issues.add(
                "checksums_missing_entry",
                "checksums.json does not cover a declared file",
                Some(declared),
            ),
        }
    }
    for path in checksum_map.keys() {
        if path != MANIFEST_FILE && !declared_paths.contains(path) {
            issues.add(
                "undeclared_file",
                "checksums.json covers a file the manifest does not declare",
                Some(path),
            );
        }
    }
    for entry in &archive.entries {
        if entry.name == MANIFEST_FILE || entry.name == CHECKSUMS_FILE {
            continue;
        }
        if !declared_paths.contains(&entry.name) {
            issues.add(
                "undeclared_file",
                "the archive contains an undeclared file",
                Some(&entry.name),
            );
        }
    }

    // The four catalog files and the relationship file must all be present and declared.
    if !legacy {
        for (path, schema) in CATALOG_FILES {
            match manifest.data.iter().find(|entry| entry.path == path) {
                Some(entry) if entry.schema_id == schema => {}
                Some(_) => issues.add(
                    "data_schema_mismatch",
                    "a data file has the wrong schema id",
                    Some(path),
                ),
                None => issues.add(
                    "missing_data_file",
                    "a required catalog data file is not declared",
                    Some(path),
                ),
            }
        }
        if manifest.data.len() != CATALOG_FILES.len() {
            issues.add(
                "unexpected_data_file",
                "the package declares a data file outside the catalog contract",
                Some(MANIFEST_FILE),
            );
        }
    }

    // Actual bytes: manifest, data, images.
    let mut record_ids = BTreeSet::new();
    let mut relationship_ids = BTreeSet::new();
    let mut records_by_category: BTreeMap<String, u64> = BTreeMap::new();
    let mut relationships = Vec::new();

    for declared in &manifest.data {
        if !names.contains(&declared.path) {
            continue;
        }
        let limit = options.max_data_file_bytes.min(options.max_total_bytes);
        let bytes = match read_named(
            &archive,
            &mut file,
            &declared.path,
            limit,
            &cancel,
            &mut issues,
        ) {
            Some(bytes) => bytes,
            None => continue,
        };
        let actual_sha = sha256_hex(&bytes);
        if bytes.len() as u64 != declared.size || actual_sha != declared.sha256 {
            issues.add(
                "data_mismatch",
                "the actual data size or SHA-256 differs from the declaration",
                Some(&declared.path),
            );
            continue;
        }
        if let Some((size, sha)) = checksum_map.get(&declared.path)
            && (*size != declared.size || *sha != declared.sha256)
        {
            issues.add(
                "declared_checksum_mismatch",
                "the manifest and checksums file disagree",
                Some(&declared.path),
            );
        }
        if declared.schema_id == "leonidaforge.catalog.relationships/1" {
            validate_relationships(
                &bytes,
                &mut relationship_ids,
                &mut relationships,
                &mut issues,
                options.max_records,
            );
        } else {
            let category = declared
                .path
                .strip_prefix("data/")
                .and_then(|name| name.strip_suffix(".ndjson"))
                .unwrap_or("");
            validate_records(
                &bytes,
                category,
                &mut record_ids,
                &mut records_by_category,
                &mut issues,
                options.max_records,
            );
        }
    }

    for category in CATEGORIES {
        let expected = manifest.counts.get(category).copied().unwrap_or(0);
        let actual = records_by_category.get(category).copied().unwrap_or(0);
        if expected != actual {
            issues.add(
                "record_count_mismatch",
                format!(
                    "the manifest declares {expected} {category} records but the file has {actual}"
                ),
                Some(&format!("data/{category}.ndjson")),
            );
        }
    }
    for relationship in &relationships {
        if !record_ids.contains(relationship) {
            issues.add(
                "relationship_target_missing",
                "a relationship names a record that is not in the package",
                Some("data/relationships.ndjson"),
            );
        }
    }

    // Images.
    for image in &manifest.images {
        if !names.contains(&image.path) {
            continue;
        }
        let bytes = match read_named(
            &archive,
            &mut file,
            &image.path,
            options.max_image_bytes,
            &cancel,
            &mut issues,
        ) {
            Some(bytes) => bytes,
            None => continue,
        };
        let actual_sha = sha256_hex(&bytes);
        if bytes.len() as u64 != image.size || actual_sha != image.sha256 {
            issues.add(
                "image_mismatch",
                "the actual image size or SHA-256 differs from the declaration",
                Some(&image.path),
            );
            continue;
        }
        if let Some((size, sha)) = checksum_map.get(&image.path)
            && (*size != image.size || *sha != image.sha256)
        {
            issues.add(
                "declared_checksum_mismatch",
                "the manifest and checksums file disagree",
                Some(&image.path),
            );
        }
        if !image_magic_matches(&bytes, &image.format) {
            issues.add(
                "image_format",
                "the image bytes do not match the declared format",
                Some(&image.path),
            );
        } else if let Some((width, height)) = image_dimensions(&bytes)
            && (width != image.width || height != image.height)
        {
            issues.add(
                "image_dimensions",
                format!(
                    "the image is {width}x{height}, the manifest declares {}x{}",
                    image.width, image.height
                ),
                Some(&image.path),
            );
        }
    }

    finish(&options, Some(&archive), Some(package_sha256), issues)
}

fn finish(
    options: &Options,
    archive: Option<&zip::Archive>,
    package_sha256: Option<String>,
    issues: Issues,
) -> Result<(), String> {
    let valid = issues.count == 0;
    let result = json!({
        "schema": "leonida-forge.package-validation/1",
        "valid": valid,
        "package": {
            "path": options.package.file_name().map(|name| name.to_string_lossy().into_owned()),
            "sha256": package_sha256,
            "entries": archive.map(|archive| archive.entries.len() as u64)
        },
        "errorCount": issues.count,
        "errors": issues.items
    });
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|err| format!("cannot serialize the result: {err}"))?
        );
    } else if valid {
        println!("package is valid");
    } else {
        println!("package is invalid: {} error(s)", issues.count);
        for issue in result["errors"].as_array().into_iter().flatten() {
            eprintln!(
                "{}: {}{}",
                issue["code"].as_str().unwrap_or("error"),
                issue["message"].as_str().unwrap_or(""),
                issue["path"]
                    .as_str()
                    .map(|path| format!(" ({path})"))
                    .unwrap_or_default()
            );
        }
    }
    if valid {
        Ok(())
    } else {
        Err(format!(
            "package validation failed with {} error(s)",
            issues.count
        ))
    }
}

fn read_named(
    archive: &zip::Archive,
    file: &mut File,
    name: &str,
    limit: u64,
    cancel: &AtomicBool,
    issues: &mut Issues,
) -> Option<Vec<u8>> {
    let entry = archive
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .cloned()
        .or_else(|| {
            issues.add(
                "missing_file",
                "a required file is not in the archive",
                Some(name),
            );
            None
        })?;
    if entry.uncompressed_size > limit {
        issues.add(
            "entry_too_large",
            format!(
                "the entry is {} bytes, above the {limit} byte limit",
                entry.uncompressed_size
            ),
            Some(name),
        );
        return None;
    }
    let len = file.metadata().ok()?.len();
    let mut bytes = Vec::new();
    match archive.decode_entry(file, len, &entry, cancel, limit, &mut bytes) {
        Ok(written) if written == entry.uncompressed_size => Some(bytes),
        Ok(written) => {
            issues.add(
                "size_mismatch",
                format!(
                    "the entry decoded to {written} bytes, the directory declares {}",
                    entry.uncompressed_size
                ),
                Some(name),
            );
            None
        }
        Err(err) => {
            issues.add("entry_decode", err.to_string(), Some(name));
            None
        }
    }
}

fn parse_json(bytes: &[u8], name: &str, issues: &mut Issues) -> Option<Value> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            issues.add(
                "invalid_encoding",
                "the file is not valid UTF-8",
                Some(name),
            );
            return None;
        }
    };
    if let Ok(Some(key)) = duplicate_key(text) {
        issues.add(
            "duplicate_json_key",
            format!("the file has a duplicate object key {:?}", key),
            Some(name),
        );
        return None;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(value) => Some(value),
        Err(err) => {
            issues.add("invalid_json", err.to_string(), Some(name));
            None
        }
    }
}

fn read_manifest(value: &Value, issues: &mut Issues) -> Option<Manifest> {
    let object = value.as_object().or_else(|| {
        issues.add(
            "manifest_object",
            "manifest.json is not an object",
            Some(MANIFEST_FILE),
        );
        None
    })?;
    let package_id_value = required_str(object, "packageId", MANIFEST_FILE, issues)?;
    if !package_id(&package_id_value) {
        issues.add(
            "package_id",
            "packageId is not a valid identifier",
            Some(MANIFEST_FILE),
        );
    }
    let created_at = required_str(object, "createdAt", MANIFEST_FILE, issues)?;
    if !iso_timestamp(&created_at) {
        issues.add(
            "created_at",
            "createdAt is not an ISO 8601 timestamp with a zone",
            Some(MANIFEST_FILE),
        );
    }
    let manifest_version = required_str(object, "manifestVersion", MANIFEST_FILE, issues)?;
    let legacy = manifest_version == LEGACY_MANIFEST_VERSION;
    let Some(exporter) = object.get("exporter").and_then(Value::as_object) else {
        issues.add(
            "exporter",
            "manifest.json has no exporter object",
            Some(MANIFEST_FILE),
        );
        return None;
    };
    let exporter_name = required_str(exporter, "name", MANIFEST_FILE, issues)?;
    let exporter_version = required_str(exporter, "version", MANIFEST_FILE, issues)?;

    let (
        catalog_schema_version,
        forge_version,
        forge_revision,
        game_build_id,
        game_build_source,
        scope_kind,
        categories,
        counts,
        limitations,
    ) = if legacy {
        (
            String::new(),
            String::new(),
            None,
            String::new(),
            None,
            "legacy".to_string(),
            Vec::new(),
            BTreeMap::new(),
            Vec::new(),
        )
    } else {
        let Some(forge) = object.get("leonidaForge").and_then(Value::as_object) else {
            issues.add(
                "leonida_forge",
                "manifest.json has no leonidaForge object",
                Some(MANIFEST_FILE),
            );
            return None;
        };
        let forge_version = required_str(forge, "version", MANIFEST_FILE, issues)?;
        let forge_revision = optional_str(forge, "gitRevision");
        let Some(game_build) = object.get("gameBuild").and_then(Value::as_object) else {
            issues.add(
                "game_build",
                "manifest.json has no gameBuild object",
                Some(MANIFEST_FILE),
            );
            return None;
        };
        let game_build_id = required_str(game_build, "identification", MANIFEST_FILE, issues)?;
        let game_build_source = optional_str(game_build, "source");

        let Some(scope) = object.get("scope").and_then(Value::as_object) else {
            issues.add(
                "scope",
                "manifest.json has no scope object",
                Some(MANIFEST_FILE),
            );
            return None;
        };
        let scope_kind = required_str(scope, "kind", MANIFEST_FILE, issues)?;
        if scope_kind != "complete" && scope_kind != "partial" {
            issues.add(
                "scope_kind",
                "scope.kind must be complete or partial",
                Some(MANIFEST_FILE),
            );
        }
        let categories = scope
            .get("categories")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if categories.is_empty() {
            issues.add(
                "scope_categories",
                "scope.categories must name at least one category",
                Some(MANIFEST_FILE),
            );
        }
        for category in &categories {
            if !CATEGORIES.contains(&category.as_str()) {
                issues.add(
                    "scope_category",
                    format!("unknown category {category}"),
                    Some(MANIFEST_FILE),
                );
            }
        }

        let mut counts = BTreeMap::new();
        if let Some(counts_object) = object.get("counts").and_then(Value::as_object) {
            for category in CATEGORIES {
                let value = counts_object
                    .get(category)
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                counts.insert(category.to_string(), value);
            }
        } else {
            issues.add(
                "counts",
                "manifest.json has no counts object",
                Some(MANIFEST_FILE),
            );
        }
        let limitations = object
            .get("limitations")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        (
            required_str(object, "catalogSchemaVersion", MANIFEST_FILE, issues).unwrap_or_default(),
            forge_version,
            forge_revision,
            game_build_id,
            game_build_source,
            scope_kind,
            categories,
            counts,
            limitations,
        )
    };

    let mut data = Vec::new();
    let mut previous = String::new();
    for entry in object
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(entry_object) = entry.as_object() else {
            issues.add(
                "data_entry",
                "a data entry is not an object",
                Some(MANIFEST_FILE),
            );
            continue;
        };
        let Some(path) = required_str(entry_object, "path", MANIFEST_FILE, issues) else {
            continue;
        };
        if !safe_path(&path) || !path.starts_with("data/") || !path.ends_with(".ndjson") {
            issues.add(
                "data_path",
                "a data path is not a safe data/ NDJSON path",
                Some(MANIFEST_FILE),
            );
        }
        if path <= previous {
            issues.add(
                "data_order",
                "data entries must be sorted by path",
                Some(MANIFEST_FILE),
            );
        }
        previous = path.clone();
        let schema_id =
            required_str(entry_object, "schemaId", MANIFEST_FILE, issues).unwrap_or_default();
        let size = required_u64(entry_object, "sizeBytes", MANIFEST_FILE, issues).unwrap_or(0);
        let sha256 =
            required_str(entry_object, "sha256", MANIFEST_FILE, issues).unwrap_or_default();
        if !sha256_is_hex(&sha256) {
            issues.add(
                "data_sha",
                "a data digest is not a lowercase SHA-256",
                Some(MANIFEST_FILE),
            );
        }
        data.push(Declared {
            path,
            schema_id,
            size,
            sha256,
        });
    }
    if data.len() > 16 {
        issues.add(
            "data_count",
            "the manifest declares too many data files",
            Some(MANIFEST_FILE),
        );
    }

    let mut images = Vec::new();
    let mut previous = String::new();
    let mut media_ids = HashSet::new();
    for entry in object
        .get("images")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(entry_object) = entry.as_object() else {
            issues.add(
                "image_entry",
                "an image entry is not an object",
                Some(MANIFEST_FILE),
            );
            continue;
        };
        let path = required_str(entry_object, "path", MANIFEST_FILE, issues).unwrap_or_default();
        if !safe_path(&path) || !path.starts_with("images/") {
            issues.add(
                "image_path",
                "an image path is not safe",
                Some(MANIFEST_FILE),
            );
        }
        if path <= previous {
            issues.add(
                "image_order",
                "image entries must be sorted by path",
                Some(MANIFEST_FILE),
            );
        }
        previous = path.clone();
        let media_id =
            required_str(entry_object, "mediaId", MANIFEST_FILE, issues).unwrap_or_default();
        if media_id.is_empty()
            || media_id.len() > MAX_MEDIA_ID
            || !media_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            issues.add("media_id", "a media id is invalid", Some(MANIFEST_FILE));
        }
        if !media_ids.insert(media_id.clone()) {
            issues.add(
                "media_id_duplicate",
                "two images share a media id",
                Some(MANIFEST_FILE),
            );
        }
        let role = required_str(entry_object, "role", MANIFEST_FILE, issues).unwrap_or_default();
        if role != "preview" && role != "gallery" {
            issues.add("media_role", "a media role is invalid", Some(MANIFEST_FILE));
        }
        let format =
            required_str(entry_object, "format", MANIFEST_FILE, issues).unwrap_or_default();
        if format != "png" && format != "webp" {
            issues.add(
                "image_format",
                "a declared image format is not png or webp",
                Some(MANIFEST_FILE),
            );
        }
        let size = required_u64(entry_object, "sizeBytes", MANIFEST_FILE, issues).unwrap_or(0);
        let sha256 =
            required_str(entry_object, "sha256", MANIFEST_FILE, issues).unwrap_or_default();
        if !sha256_is_hex(&sha256) {
            issues.add(
                "image_sha",
                "an image digest is not a lowercase SHA-256",
                Some(MANIFEST_FILE),
            );
        }
        let width = required_u64(entry_object, "width", MANIFEST_FILE, issues).unwrap_or(0);
        let height = required_u64(entry_object, "height", MANIFEST_FILE, issues).unwrap_or(0);
        if !(1..=16_384).contains(&width) || !(1..=16_384).contains(&height) {
            issues.add(
                "image_dimensions",
                "image dimensions are out of range",
                Some(MANIFEST_FILE),
            );
        }
        images.push(ImageDeclared {
            path,
            format,
            size,
            sha256,
            width,
            height,
        });
    }
    if images.len() > 256 {
        issues.add(
            "image_count",
            "the manifest declares too many images",
            Some(MANIFEST_FILE),
        );
    }

    Some(Manifest {
        package_id: package_id_value,
        manifest_version,
        catalog_schema_version,
        created_at,
        exporter_name,
        exporter_version,
        forge_version,
        forge_revision,
        game_build: game_build_id,
        game_build_source,
        scope_kind,
        categories,
        counts,
        limitations,
        data,
        images,
    })
}

fn package_id_of(value: &Value) -> String {
    value
        .get("packageId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn declared_entry_size(manifest: &Manifest, path: &str) -> Option<u64> {
    manifest
        .data
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.size)
        .or_else(|| {
            manifest
                .images
                .iter()
                .find(|entry| entry.path == path)
                .map(|entry| entry.size)
        })
}

fn required_str(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
    issues: &mut Issues,
) -> Option<String> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() && value.len() <= 512 => Some(value.to_string()),
        _ => {
            issues.add(
                "missing_field",
                format!("{key} is missing or not a non-empty string"),
                Some(path),
            );
            None
        }
    }
}

fn optional_str(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

fn required_u64(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
    issues: &mut Issues,
) -> Option<u64> {
    match object.get(key).and_then(Value::as_u64) {
        Some(value) => Some(value),
        None => {
            issues.add(
                "missing_field",
                format!("{key} is missing or not a non-negative integer"),
                Some(path),
            );
            None
        }
    }
}

fn validate_records(
    bytes: &[u8],
    category: &str,
    ids: &mut BTreeSet<String>,
    counts: &mut BTreeMap<String, u64>,
    issues: &mut Issues,
    max_records: u64,
) {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            issues.add(
                "invalid_encoding",
                "a data file is not valid UTF-8",
                Some(&format!("data/{category}.ndjson")),
            );
            return;
        }
    };
    let path = format!("data/{category}.ndjson");
    let mut total = 0u64;
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        total += 1;
        if total > max_records {
            issues.add(
                "too_many_records",
                "the data file exceeds the record limit",
                Some(&path),
            );
            return;
        }
        if line.len() > MAX_LINE_BYTES {
            issues.add(
                "record_too_large",
                "a record line is too large",
                Some(&path),
            );
            continue;
        }
        if let Ok(Some(key)) = duplicate_key(line) {
            issues.add(
                "duplicate_json_key",
                format!("line {} has a duplicate object key {:?}", number + 1, key),
                Some(&path),
            );
            continue;
        }
        let record = match serde_json::from_str::<Value>(line) {
            Ok(record) => record,
            Err(err) => {
                issues.add(
                    "invalid_json",
                    format!("line {}: {err}", number + 1),
                    Some(&path),
                );
                continue;
            }
        };
        if let Err(error) = validate_record(&record, category) {
            issues.add(
                &error.0,
                format!("line {}: {}", number + 1, error.1),
                Some(&path),
            );
            continue;
        }
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !ids.insert(id.clone()) {
            issues.add(
                "duplicate_id",
                format!("record id {id} occurs more than once"),
                Some(&path),
            );
        }
    }
    counts.insert(category.to_string(), total);
}

fn validate_record(record: &Value, category: &str) -> Result<(), (String, String)> {
    let object = record.as_object().ok_or_else(|| {
        (
            "record_object".to_string(),
            "the record is not an object".to_string(),
        )
    })?;
    if object.get("schema").and_then(Value::as_str) != Some(RECORD_SCHEMA) {
        return Err((
            "record_schema".to_string(),
            format!("the record schema is not {RECORD_SCHEMA}"),
        ));
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ("record_id".to_string(), "the record has no id".to_string()))?;
    if !record_id(id) {
        return Err((
            "record_id".to_string(),
            format!("{id} is not a valid record id"),
        ));
    }
    if object.get("category").and_then(Value::as_str) != Some(category) {
        return Err((
            "record_category".to_string(),
            "the record category does not match its file".to_string(),
        ));
    }
    let entity = object
        .get("entityType")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "record_entity".to_string(),
                "the record has no entityType".to_string(),
            )
        })?;
    if entity.is_empty()
        || entity.len() > 64
        || !entity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err((
            "record_entity".to_string(),
            "entityType is not a lowercase identifier".to_string(),
        ));
    }
    let name = object
        .get("internalName")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                "record_name".to_string(),
                "the record has no internalName".to_string(),
            )
        })?;
    if name.is_empty() || name.len() > 1024 {
        return Err((
            "record_name".to_string(),
            "internalName is empty or too long".to_string(),
        ));
    }
    if let Some(display) = object.get("displayName")
        && !display.is_null()
        && !display
            .as_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= 512)
    {
        return Err((
            "record_display".to_string(),
            "displayName is neither null nor a string".to_string(),
        ));
    }
    let sources = object
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            (
                "record_sources".to_string(),
                "the record has no sources".to_string(),
            )
        })?;
    if sources.is_empty() || sources.len() > 64 {
        return Err((
            "record_sources".to_string(),
            "sources must hold 1 to 64 entries".to_string(),
        ));
    }
    for source in sources {
        let source = source.as_object().ok_or_else(|| {
            (
                "record_source".to_string(),
                "a source is not an object".to_string(),
            )
        })?;
        let id = source.get("id").and_then(Value::as_str).ok_or_else(|| {
            (
                "record_source".to_string(),
                "a source has no id".to_string(),
            )
        })?;
        if id.is_empty() || id.contains(['/', '\\']) || id.len() > 128 {
            return Err((
                "record_source".to_string(),
                "a source id is invalid".to_string(),
            ));
        }
        if let Some(row) = source.get("row")
            && !row.is_null()
            && row.as_u64().is_none()
        {
            return Err((
                "record_source".to_string(),
                "a source row is not an integer".to_string(),
            ));
        }
        let sha = source
            .get("payloadSha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "record_source".to_string(),
                    "a source has no payloadSha256".to_string(),
                )
            })?;
        if !sha256_is_hex(sha) {
            return Err((
                "record_source".to_string(),
                "a source digest is not a SHA-256".to_string(),
            ));
        }
        if source.get("verification").and_then(Value::as_str).is_none() {
            return Err((
                "record_source".to_string(),
                "a source has no verification state".to_string(),
            ));
        }
    }
    let fields = object
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            (
                "record_fields".to_string(),
                "fields is not an object".to_string(),
            )
        })?;
    if fields.len() > 4096 {
        return Err((
            "record_fields".to_string(),
            "the record has too many fields".to_string(),
        ));
    }
    for (key, field) in fields {
        if key.is_empty() || key.len() > 256 {
            return Err((
                "record_field".to_string(),
                "a field name is empty or too long".to_string(),
            ));
        }
        let field = field.as_object().ok_or_else(|| {
            (
                "record_field".to_string(),
                format!("field {key} is not an object"),
            )
        })?;
        if field.get("value").is_none() {
            return Err((
                "record_field".to_string(),
                format!("field {key} has no value"),
            ));
        }
        if !field.get("unit").is_some_and(Value::is_null)
            && !field
                .get("unit")
                .and_then(Value::as_str)
                .is_some_and(|unit| !unit.is_empty())
        {
            return Err((
                "record_field".to_string(),
                format!("field {key} has an invalid unit"),
            ));
        }
        if field
            .get("semantics")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err((
                "record_field".to_string(),
                format!("field {key} has no semantics"),
            ));
        }
    }
    if !object.get("metadata").is_some_and(Value::is_object) {
        return Err((
            "record_metadata".to_string(),
            "metadata is not an object".to_string(),
        ));
    }
    if let Some(hashes) = object.get("hashes") {
        if !hashes.is_array() {
            return Err((
                "record_hashes".to_string(),
                "hashes is not an array".to_string(),
            ));
        }
    } else {
        return Err((
            "record_hashes".to_string(),
            "the record has no hashes array".to_string(),
        ));
    }
    let provenance = object
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            (
                "record_provenance".to_string(),
                "provenance is not an object".to_string(),
            )
        })?;
    if provenance
        .get("verification")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err((
            "record_provenance".to_string(),
            "provenance has no verification state".to_string(),
        ));
    }
    Ok(())
}

fn validate_relationships(
    bytes: &[u8],
    ids: &mut BTreeSet<String>,
    targets: &mut Vec<String>,
    issues: &mut Issues,
    max_records: u64,
) {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            issues.add(
                "invalid_encoding",
                "relationships.ndjson is not valid UTF-8",
                Some("data/relationships.ndjson"),
            );
            return;
        }
    };
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for (number, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        total += 1;
        if total > max_records {
            issues.add(
                "too_many_records",
                "relationships.ndjson exceeds the record limit",
                Some("data/relationships.ndjson"),
            );
            return;
        }
        if line.len() > MAX_LINE_BYTES {
            issues.add(
                "record_too_large",
                "a relationship line is too large",
                Some("data/relationships.ndjson"),
            );
            continue;
        }
        if let Ok(Some(key)) = duplicate_key(line) {
            issues.add(
                "duplicate_json_key",
                format!("line {} has a duplicate object key {:?}", number + 1, key),
                Some("data/relationships.ndjson"),
            );
            continue;
        }
        let value = match serde_json::from_str::<Value>(line) {
            Ok(value) => value,
            Err(err) => {
                issues.add(
                    "invalid_json",
                    format!("line {}: {err}", number + 1),
                    Some("data/relationships.ndjson"),
                );
                continue;
            }
        };
        let Some(object) = value.as_object() else {
            issues.add(
                "relationship_object",
                "a relationship is not an object",
                Some("data/relationships.ndjson"),
            );
            continue;
        };
        if object.get("schema").and_then(Value::as_str) != Some(RELATIONSHIP_SCHEMA) {
            issues.add(
                "relationship_schema",
                "a relationship schema is invalid",
                Some("data/relationships.ndjson"),
            );
        }
        let Some(id) = object.get("id").and_then(Value::as_str) else {
            issues.add(
                "relationship_id",
                "a relationship has no id",
                Some("data/relationships.ndjson"),
            );
            continue;
        };
        if !record_id(id) || !ids.insert(id.to_string()) {
            issues.add(
                "relationship_id",
                "a relationship id is invalid or duplicated",
                Some("data/relationships.ndjson"),
            );
        }
        let from = object
            .get("from")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let to = object.get("to").and_then(Value::as_str).unwrap_or_default();
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if from.is_empty() || to.is_empty() || kind.is_empty() {
            issues.add(
                "relationship_fields",
                "a relationship is missing from, to or type",
                Some("data/relationships.ndjson"),
            );
            continue;
        }
        if !seen.insert((from.to_string(), to.to_string(), kind.to_string())) {
            issues.add(
                "relationship_duplicate",
                "a relationship is declared twice",
                Some("data/relationships.ndjson"),
            );
        }
        targets.push(from.to_string());
        targets.push(to.to_string());
    }
}

fn image_dimensions(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) && bytes.len() >= 24 {
        let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        return Some((u64::from(width), u64::from(height)));
    }
    if bytes.len() >= 30 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        match &bytes[12..16] {
            b"VP8X" => {
                let width = 1
                    + u64::from(bytes[24])
                    + (u64::from(bytes[25]) << 8)
                    + (u64::from(bytes[26]) << 16);
                let height = 1
                    + u64::from(bytes[27])
                    + (u64::from(bytes[28]) << 8)
                    + (u64::from(bytes[29]) << 16);
                return Some((width, height));
            }
            b"VP8 " => {
                let width = u64::from(u16::from_le_bytes([bytes[26], bytes[27]]) & 0x3fff);
                let height = u64::from(u16::from_le_bytes([bytes[28], bytes[29]]) & 0x3fff);
                return Some((width, height));
            }
            b"VP8L" if bytes.len() >= 25 => {
                let bits = u32::from_le_bytes(bytes[21..25].try_into().ok()?);
                return Some((
                    1 + u64::from(bits & 0x3fff),
                    1 + u64::from((bits >> 14) & 0x3fff),
                ));
            }
            _ => {}
        }
    }
    None
}

fn image_magic_matches(bytes: &[u8], format: &str) -> bool {
    match format {
        "png" => bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]),
        "webp" => bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP",
        _ => false,
    }
}

fn sha256_file(file: &mut File) -> Result<String, String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))
        .map_err(|err| format!("cannot rewind the package: {err}"))?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("cannot read the package: {err}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
