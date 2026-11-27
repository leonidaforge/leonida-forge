//! The preview manifest the exporter reads.
//!
//! One entry per image. The document is keyed by model name, not by catalog
//! identifier: the exporter owns identifier generation and resolves the model
//! to its canonical record, so no second normalisation can drift from it.

use std::path::Path;

use serde_json::{Value, json};

/// The schema of the preview manifest.
pub const PREVIEWS_SCHEMA: &str = "leonida-forge.vehicle-previews/1";
/// The role of a primary image.
pub const ROLE_PRIMARY: &str = "preview";
/// The role of a card thumbnail.
pub const ROLE_THUMBNAIL: &str = "thumbnail";
/// The manifest file name inside the preview directory.
pub const MANIFEST_FILE: &str = "previews.json";

/// One image entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// The model the image was rendered from.
    pub model: String,
    /// `preview` or `thumbnail`.
    pub role: String,
    /// The file name, relative to the manifest.
    pub file: String,
    pub width: u32,
    pub height: u32,
    /// SHA-256 of the file.
    pub sha256: String,
    /// Alternative text for the rendered body.
    pub alt: String,
}

/// Writes the manifest with sorted entries.
pub fn write(directory: &Path, images: &[Image]) -> Result<(), String> {
    let mut images: Vec<&Image> = images.iter().collect();
    images.sort_by(|left, right| {
        left.model
            .cmp(&right.model)
            .then_with(|| left.role.cmp(&right.role))
    });
    let document = json!({
        "schema": PREVIEWS_SCHEMA,
        "images": images
            .iter()
            .map(|image| json!({
                "model": image.model,
                "role": image.role,
                "file": image.file,
                "width": image.width,
                "height": image.height,
                "sha256": image.sha256,
                "alt": image.alt,
            }))
            .collect::<Vec<Value>>(),
    });
    let bytes = serde_json::to_vec_pretty(&document).map_err(|err| err.to_string())?;
    super::cache::write_atomic(&directory.join(MANIFEST_FILE), &bytes)
}

/// Reads the manifest back.
pub fn read(directory: &Path) -> Result<Vec<Image>, String> {
    let path = directory.join(MANIFEST_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|err| format!("{} is not JSON: {err}", path.display()))?;
    if value.get("schema").and_then(Value::as_str) != Some(PREVIEWS_SCHEMA) {
        return Err(format!(
            "{} is not a {PREVIEWS_SCHEMA} document",
            path.display()
        ));
    }
    let entries = value
        .get("images")
        .and_then(Value::as_array)
        .ok_or("the manifest has no images array")?;
    let mut images = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = |name: &str| {
            entry
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("an image entry has no {name}"))
        };
        images.push(Image {
            model: field("model")?,
            role: field("role")?,
            file: field("file")?,
            width: entry
                .get("width")
                .and_then(Value::as_u64)
                .ok_or("an image entry has no width")? as u32,
            height: entry
                .get("height")
                .and_then(Value::as_u64)
                .ok_or("an image entry has no height")? as u32,
            sha256: field("sha256")?,
            alt: field("alt")?,
        });
    }
    Ok(images)
}

/// The alternative text for a rendered body image.
pub fn alt_text(model: &str, thumbnail: bool) -> String {
    if thumbnail {
        format!("{model} vehicle model, thumbnail view")
    } else {
        format!("{model} vehicle model rendered from the retail game files, three-quarter view")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(model: &str, role: &str) -> Image {
        Image {
            model: model.to_string(),
            role: role.to_string(),
            file: format!("{model}-{role}.webp"),
            width: 1024,
            height: 1024,
            sha256: "0".repeat(64),
            alt: alt_text(model, role == ROLE_THUMBNAIL),
        }
    }

    #[test]
    fn a_manifest_round_trips_and_sorts_by_model_then_role() {
        let directory = tempfile::tempdir().expect("tempdir");
        let images = vec![
            image("sultan", ROLE_PRIMARY),
            image("akane", ROLE_THUMBNAIL),
            image("akane", ROLE_PRIMARY),
        ];
        write(directory.path(), &images).expect("write");
        let read_back = read(directory.path()).expect("read");
        assert_eq!(read_back.len(), 3);
        assert_eq!(read_back[0].model, "akane");
        assert_eq!(
            read_back[0].role, ROLE_PRIMARY,
            "preview sorts before thumbnail"
        );
        assert_eq!(read_back[1].role, ROLE_THUMBNAIL);
        assert_eq!(read_back[2].model, "sultan");
    }

    #[test]
    fn a_document_with_the_wrong_schema_is_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            directory.path().join(MANIFEST_FILE),
            br#"{"schema":"other/1","images":[]}"#,
        )
        .expect("write");
        assert!(read(directory.path()).is_err());
    }
}
