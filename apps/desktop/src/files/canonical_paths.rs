//! Canonical resource paths for the acceptance resources.
//!
//! One ignored test resolves a list of technical row selectors through the same
//! path the explorer uses and prints the canonical path, the stable identity and
//! the limitations the path model reports. It exists so the acceptance document
//! quotes paths the application produces rather than paths typed by hand.
//!
//! `LF_PATH_CASES` names a list of selectors, one per line, as
//! `<archive>!<row>!<row>` with an optional `member=<index>` suffix.
//! `LF_TEST_GAME_ROOT` and `LF_TEST_EXECUTABLE` name the installation.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use super::*;
use crate::files::model;
use crate::files::{Entry, EntryKind, Executable, list_with};
use lforge_scene::Scene;

#[test]
#[ignore = "requires LF_PATH_CASES, LF_TEST_GAME_ROOT and LF_TEST_EXECUTABLE"]
fn reports_canonical_resource_paths() {
    let list = std::env::var("LF_PATH_CASES").expect("LF_PATH_CASES");
    let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
    let executable = std::env::var("LF_TEST_EXECUTABLE").expect("LF_TEST_EXECUTABLE");
    let access = Access::with(Arc::new(
        Executable::open(Path::new(&executable)).expect("executable"),
    ));
    let cancel = AtomicBool::new(false);
    let root = Path::new(&root);
    let text = std::fs::read_to_string(&list).expect("case list");
    let mut resolved = std::collections::BTreeMap::new();
    let mut index = std::collections::HashMap::new();
    let mut found = 0usize;

    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let (selector, rest) = match line.split_once(" member=") {
            Some((selector, member)) => (selector, Some(member)),
            None => (line, None),
        };
        let Some((parent_chain, row)) = selector.rsplit_once('!') else {
            println!("{selector}: not a selector");
            continue;
        };
        let Ok(row) = row.parse::<usize>() else {
            println!("{selector}: the last component is not a row");
            continue;
        };
        let Some(parent) =
            super::tests::resolve_chain(root, &access, parent_chain, &mut resolved, &mut index)
        else {
            println!("{selector}: the archive chain did not resolve");
            continue;
        };
        // A row of an archive that has folders sits under them, so the row is
        // found by walking down. Nested archives list flat.
        let mut listings = 0usize;
        let found_entry = find_row(&parent, row as u32, &access, 8, &mut listings);
        let Some(entry) = found_entry else {
            println!("{selector}: no entry carries that row in {listings} listing(s)");
            continue;
        };
        let entry = &entry;
        found += 1;
        let path = entry
            .resource
            .as_ref()
            .map(|resource| resource.display())
            .unwrap_or_else(|| "<no canonical path>".to_string());
        let identity = entry
            .resource
            .as_ref()
            .map(|resource| resource.identity())
            .unwrap_or_default();
        let limitations = entry
            .resource
            .as_ref()
            .map(|resource| resource.limitations())
            .unwrap_or_default();
        println!("{selector}");
        println!("  name: {}", entry.name);
        println!("  type: {:?}", entry.resource_type);
        println!("  canonical: {path}");
        println!("  identity: {identity}");
        if !limitations.is_empty() {
            println!("  limitations: {}", limitations.join("; "));
        }
        // The entry label is the stored key when the name index does not
        // resolve it, so the model's own declared name is what the acceptance
        // document quotes beside the path.
        let kind = match model::classify_resource(&entry.path, &access, &cancel) {
            Ok(kind) => kind,
            Err(err) => {
                println!("  model: does not classify: {err}");
                continue;
            }
        };
        let member_index = rest.and_then(|member| member.parse::<usize>().ok());
        let describes = |scene: &Scene, name: &str| {
            format!(
                "{name} ({} bone(s), {} primitive(s))",
                scene
                    .skeleton
                    .as_ref()
                    .map_or(0, |skeleton| skeleton.bones.len()),
                scene
                    .meshes
                    .iter()
                    .map(|mesh| mesh.primitives.len())
                    .sum::<usize>()
            )
        };
        let described = match (kind, member_index) {
            (model::ResourceKind::Dictionary, index) => {
                let index = index.unwrap_or(0);
                model::load_dictionary_member(&entry.path, &access, Some(root), index, &cancel)
                    .map(|loaded| describes(&loaded.scene, &loaded.name))
            }
            _ => model::load_with_cancel(&entry.path, &access, Some(root), &cancel)
                .map(|loaded| describes(&loaded.scene, &loaded.name)),
        };
        match described {
            Ok(text) => println!("  model: {text}"),
            Err(err) => println!("  model: does not load: {err}"),
        }
        if matches!(kind, model::ResourceKind::Dictionary)
            && let Ok(info) = model::enumerate_dictionary(&entry.path, &access, &cancel)
        {
            println!("  dictionary members: {}", info.info.members.len());
        }
    }
    assert!(found > 0, "no selector resolved");
}

/// The entry carrying `row`, walking down the folder listings of `path`.
fn find_row(
    path: &Path,
    row: u32,
    access: &Access,
    depth: usize,
    listings: &mut usize,
) -> Option<Entry> {
    if depth == 0 || *listings >= 400 {
        return None;
    }
    *listings += 1;
    let entries = list_with(path, access).ok()?;
    if let Some(found) = entries.iter().find(|entry| entry.resource_row == Some(row)) {
        return Some(found.clone());
    }
    for entry in entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Directory)
    {
        if let Some(found) = find_row(&entry.path, row, access, depth - 1, listings) {
            return Some(found);
        }
    }
    None
}
