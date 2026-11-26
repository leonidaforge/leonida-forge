//! Synthetic publication packages for validation tests.

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::{Value, json};

use super::*;

pub struct Fixture {
    pub files: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    pub fn valid() -> Self {
        let vehicle = record("vehicle-test-00000000", "vehicles", "vehicle", "TestCar");
        let ped = record("ped-test-00000000", "peds", "ped_schedule", "TestPed");
        let weapon = record(
            "weapon-test-00000000",
            "weapons",
            "weapon_type",
            "WEAPON_TEST",
        );
        let relationship = json!({
            "schema": "leonidaforge.catalog.relationship/1",
            "id": "rel-00000000",
            "from": vehicle["id"],
            "to": ped["id"],
            "type": "test_relation",
            "provenance": { "verification": "verified_structure", "notes": [] }
        });
        let data = [
            (
                "data/clothing.ndjson",
                "leonidaforge.catalog.clothing/1",
                vec![],
            ),
            ("data/peds.ndjson", "leonidaforge.catalog.peds/1", vec![ped]),
            (
                "data/relationships.ndjson",
                "leonidaforge.catalog.relationships/1",
                vec![relationship],
            ),
            (
                "data/vehicles.ndjson",
                "leonidaforge.catalog.vehicles/1",
                vec![vehicle],
            ),
            (
                "data/weapons.ndjson",
                "leonidaforge.catalog.weapons/1",
                vec![weapon],
            ),
        ];
        let mut files = BTreeMap::new();
        let mut declared = Vec::new();
        for (path, schema, values) in data {
            let bytes = ndjson(&values);
            declared.push(json!({
                "path": path,
                "schemaId": schema,
                "sizeBytes": bytes.len(),
                "sha256": sha256_hex(&bytes)
            }));
            files.insert(path.to_string(), bytes);
        }
        let manifest = json!({
            "manifestVersion": MANIFEST_VERSION,
            "catalogSchemaVersion": "1",
            "packageId": "synthetic-package",
            "createdAt": "2026-11-26T00:00:00Z",
            "exporter": { "name": "test", "version": "1" },
            "leonidaForge": { "version": "0.1.0" },
            "gameBuild": { "identification": "synthetic" },
            "scope": {
                "kind": "partial",
                "categories": ["peds", "weapons", "vehicles", "clothing"],
                "sources": [{ "id": "fixture", "rows": 3, "status": "partial" }]
            },
            "counts": { "peds": 1, "weapons": 1, "vehicles": 1, "clothing": 0 },
            "limitations": ["synthetic"],
            "data": declared,
            "images": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
        files.insert(MANIFEST_FILE.to_string(), manifest_bytes.clone());
        let mut checksum_files = BTreeMap::new();
        for (path, bytes) in &files {
            checksum_files.insert(
                path.clone(),
                json!({ "sizeBytes": bytes.len(), "sha256": sha256_hex(bytes) }),
            );
        }
        let checksums = json!({
            "checksumsVersion": "1",
            "packageId": "synthetic-package",
            "files": checksum_files
        });
        files.insert(
            CHECKSUMS_FILE.to_string(),
            serde_json::to_vec(&checksums).expect("checksums"),
        );
        Self { files }
    }

    /// A version 1.0.0 package with no catalog data, as Phase 3A accepted.
    pub fn legacy() -> Self {
        let mut files = BTreeMap::new();
        let manifest = json!({
            "manifestVersion": LEGACY_MANIFEST_VERSION,
            "packageId": "legacy-package",
            "createdAt": "2026-11-26T00:00:00Z",
            "exporter": { "name": "test", "version": "1" },
            "data": [],
            "images": []
        });
        let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
        files.insert(MANIFEST_FILE.to_string(), manifest_bytes.clone());
        let mut checksum_files = BTreeMap::new();
        checksum_files.insert(
            MANIFEST_FILE.to_string(),
            json!({ "sizeBytes": manifest_bytes.len(), "sha256": sha256_hex(&manifest_bytes) }),
        );
        let checksums = json!({
            "checksumsVersion": "1",
            "packageId": "legacy-package",
            "files": checksum_files
        });
        files.insert(
            CHECKSUMS_FILE.to_string(),
            serde_json::to_vec(&checksums).expect("checksums"),
        );
        Self { files }
    }

    pub fn write(&self, directory: &std::path::Path) -> std::path::PathBuf {
        let path = directory.join("package.zip");
        let file = std::fs::File::create(&path).expect("create package");
        let mut zip = ::zip::ZipWriter::new(file);
        let options = ::zip::write::SimpleFileOptions::default()
            .compression_method(::zip::CompressionMethod::Deflated);
        for (name, bytes) in &self.files {
            zip.start_file(name.as_str(), options).expect("start file");
            zip.write_all(bytes).expect("write file");
        }
        zip.finish().expect("finish");
        path
    }

    pub fn replace_manifest_text(&mut self, from: &str, to: &str) {
        let manifest = self.files.get_mut(MANIFEST_FILE).expect("manifest");
        let text = String::from_utf8(manifest.clone()).expect("utf8");
        *manifest = text.replace(from, to).into_bytes();
    }
}

fn record(id: &str, category: &str, entity_type: &str, name: &str) -> Value {
    json!({
        "schema": RECORD_SCHEMA,
        "id": id,
        "category": category,
        "entityType": entity_type,
        "internalName": name,
        "displayName": null,
        "aliases": [],
        "hashes": [],
        "sources": [{
            "id": "fixture",
            "row": 1,
            "payloadSha256": "a".repeat(64),
            "root": "Fixture",
            "path": "/Fixture/Item[1]",
            "verification": "verified_structure"
        }],
        "fields": {},
        "metadata": {},
        "provenance": { "verification": "verified_structure", "observationCount": 1, "notes": [] }
    })
}

fn ndjson(values: &[Value]) -> Vec<u8> {
    let mut text = String::new();
    for value in values {
        text.push_str(&serde_json::to_string(value).expect("record"));
        text.push('\n');
    }
    text.into_bytes()
}

fn options(path: std::path::PathBuf) -> Options {
    Options {
        package: path,
        json: true,
        max_package_bytes: 16 * 1024 * 1024,
        max_total_bytes: 16 * 1024 * 1024,
        max_data_file_bytes: 8 * 1024 * 1024,
        max_image_bytes: 1024 * 1024,
        max_entries: 64,
        max_compression_ratio: 100,
        max_records: 1000,
    }
}

fn run_fixture(fixture: &Fixture) -> Result<(), String> {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = fixture.write(directory.path());
    run(options(path))
}

#[test]
fn accepts_a_valid_package() {
    assert!(run_fixture(&Fixture::valid()).is_ok());
}

#[test]
fn accepts_a_legacy_package_without_catalog_data() {
    assert!(run_fixture(&Fixture::legacy()).is_ok());
}

#[test]
fn rejects_a_tampered_data_file() {
    let mut fixture = Fixture::valid();
    fixture
        .files
        .get_mut("data/vehicles.ndjson")
        .expect("vehicles")
        .extend_from_slice(b"\n");
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_an_unsupported_manifest_version() {
    let mut fixture = Fixture::valid();
    fixture.replace_manifest_text("\"1.1.0\"", "\"9.9.9\"");
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_an_unsupported_catalog_schema() {
    let mut fixture = Fixture::valid();
    fixture.replace_manifest_text(
        "\"catalogSchemaVersion\":\"1\"",
        "\"catalogSchemaVersion\":\"9\"",
    );
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_an_unsafe_archive_path() {
    let mut fixture = Fixture::valid();
    fixture
        .files
        .insert("../escape.txt".to_string(), b"no".to_vec());
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_a_duplicate_json_key() {
    let mut fixture = Fixture::valid();
    fixture.replace_manifest_text(
        "\"packageId\":\"synthetic-package\"",
        "\"packageId\":\"synthetic-package\",\"packageId\":\"synthetic-package\"",
    );
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_a_duplicate_record_id() {
    let mut fixture = Fixture::valid();
    let ped = record("vehicle-test-00000000", "peds", "ped_schedule", "Duplicate");
    let bytes = ndjson(&[ped]);
    let path = "data/peds.ndjson";
    let old_size = fixture.files.get(path).expect("peds").len();
    let checksum = sha256_hex(&bytes);
    fixture.files.insert(path.to_string(), bytes.clone());
    // The manifest still declares the original size and digest, so the package is rejected even
    // before the identity check. Update both declarations to reach the identity check.
    let manifest = fixture.files.get_mut(MANIFEST_FILE).expect("manifest");
    let text = String::from_utf8(manifest.clone())
        .expect("utf8")
        .replace(
            &format!("\"path\":\"{path}\",\"schemaId\":\"leonidaforge.catalog.peds/1\",\"sizeBytes\":{old_size}"),
            &format!("\"path\":\"{path}\",\"schemaId\":\"leonidaforge.catalog.peds/1\",\"sizeBytes\":{}", bytes.len()),
        );
    *manifest = text.into_bytes();
    let checksums = fixture.files.get_mut(CHECKSUMS_FILE).expect("checksums");
    let text = String::from_utf8(checksums.clone())
        .expect("utf8")
        .replace(&sha256_hex(&ndjson(&[])), &checksum);
    *checksums = text.into_bytes();
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_a_relationship_with_a_missing_target() {
    let mut fixture = Fixture::valid();
    let relationship = json!({
        "schema": "leonidaforge.catalog.relationship/1",
        "id": "rel-bad-00000000",
        "from": "vehicle-test-00000000",
        "to": "missing-record",
        "type": "test_relation",
        "provenance": { "verification": "verified_structure", "notes": [] }
    });
    fixture.files.insert(
        "data/relationships.ndjson".to_string(),
        ndjson(&[relationship]),
    );
    assert!(run_fixture(&fixture).is_err());
}

#[test]
fn rejects_a_missing_required_data_file() {
    let mut fixture = Fixture::valid();
    fixture.files.remove("data/clothing.ndjson");
    assert!(run_fixture(&fixture).is_err());
}
