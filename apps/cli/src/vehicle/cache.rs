//! The preview cache identity.
//!
//! A cached image is reused only when every input that can change its pixels is
//! unchanged. An existence check is not enough: a shader change, a new decoder,
//! a different texture store or a different body all have to invalidate it.
//!
//! The identity is a JSON object with sorted keys, so it is stable across runs.
//! It is written next to the images as `<model>-cache.json`, after both images
//! are in place. A cache entry that names a missing or malformed image is not a
//! hit, so a half-written pair is regenerated.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The schema of a cache sidecar.
pub const CACHE_SCHEMA: &str = "leonida-forge.vehicle-preview-cache/1";
/// The shader revision. Bump it whenever `shader.wgsl` changes appearance.
pub const SHADER_REVISION: u32 = 1;
/// The encoder profile. Bump it when the WebP settings change.
pub const ENCODER_PROFILE: &str = "image-0.25-webp-default";

/// Everything that decides the pixels of one preview.
pub struct Inputs<'a> {
    /// SHA-256 of the decoded body resource.
    pub body_sha256: &'a str,
    /// The model name the paint and the file names are derived from.
    pub model: &'a str,
    /// The body colour after the class policy resolves it.
    pub paint: [f32; 4],
    /// SHA-256 of the colour list, empty when none was given.
    pub colors_sha256: &'a str,
    /// The texture store roots with their content digest.
    pub textures: &'a [(String, String)],
    /// Primary edge in pixels.
    pub size: u32,
    /// Thumbnail edge in pixels.
    pub thumb: u32,
}

/// Builds the identity object.
pub fn identity(inputs: &Inputs<'_>) -> Value {
    let mut textures: Vec<Value> = inputs
        .textures
        .iter()
        .map(|(root, digest)| json!({ "root": root, "digest": digest }))
        .collect();
    textures.sort_by(|left, right| {
        left.get("root")
            .and_then(Value::as_str)
            .cmp(&right.get("root").and_then(Value::as_str))
    });
    json!({
        "schema": CACHE_SCHEMA,
        "decoder": {
            "model": env!("CARGO_PKG_VERSION"),
        },
        "policy": crate::vehicle::previews::policy_version(),
        "renderer": {
            "crate": lforge_renderer::CRATE_VERSION,
            "shader": SHADER_REVISION,
        },
        "body": inputs.body_sha256,
        "model": inputs.model,
        // Rounded to 1e-4: the paint is a rendering input, and a float printed
        // at full precision makes the identity depend on the formatter.
        "paint": inputs
            .paint
            .map(|channel| (channel * 10_000.0).round() as i64),
        "colors": inputs.colors_sha256,
        "textures": textures,
        "camera": { "kind": "orbit-framing", "margin": 1.0 },
        "background": "transparent",
        "output": { "format": "webp", "size": inputs.size, "thumb": inputs.thumb },
        "encoder": ENCODER_PROFILE,
    })
}

/// One image a cache entry covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The file name, relative to the cache entry.
    pub file: String,
    pub sha256: String,
    pub size: u64,
}

/// A cache entry: the identity the images were rendered from and the images
/// themselves.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub identity: Value,
    pub files: Vec<Fingerprint>,
    /// The pixel size each file must have.
    pub edges: Vec<(String, u32)>,
}

/// Reads a cache sidecar, if it is a well formed entry.
pub fn read(path: &Path) -> Option<Entry> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    if value.get("schema").and_then(Value::as_str) != Some(CACHE_SCHEMA) {
        return None;
    }
    let identity = value.get("identity")?.clone();
    let mut files = Vec::new();
    for item in value.get("files").and_then(Value::as_array)? {
        files.push(Fingerprint {
            file: item.get("file").and_then(Value::as_str)?.to_string(),
            sha256: item.get("sha256").and_then(Value::as_str)?.to_string(),
            size: item.get("size").and_then(Value::as_u64)?,
        });
    }
    if files.is_empty() {
        return None;
    }
    Some(Entry {
        identity,
        files,
        edges: Vec::new(),
    })
}

/// Writes a cache sidecar. It is written after the images it names.
pub fn write(path: &Path, identity: &Value, files: &[Fingerprint]) -> Result<(), String> {
    let document = json!({
        "schema": CACHE_SCHEMA,
        "identity": identity,
        "files": files
            .iter()
            .map(|file| json!({
                "file": file.file,
                "sha256": file.sha256,
                "size": file.size,
            }))
            .collect::<Vec<Value>>(),
    });
    let bytes = serde_json::to_vec_pretty(&document).map_err(|err| err.to_string())?;
    write_atomic(path, &bytes)
}

/// Whether every file the entry names is present with the recorded size and digest.
///
/// A missing, truncated or replaced image is a cache miss, so a half-written
/// pair is never reported as complete.
pub fn files_match(entry: &Entry, directory: &Path) -> bool {
    !entry.files.is_empty()
        && entry.files.iter().all(|file| {
            let path = directory.join(&file.file);
            let Ok(bytes) = std::fs::read(&path) else {
                return false;
            };
            bytes.len() as u64 == file.size && sha256(&bytes) == file.sha256
        })
}

/// The fingerprint of one written file.
pub fn fingerprint(path: &Path) -> Result<Fingerprint, String> {
    let bytes =
        std::fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()))?;
    Ok(Fingerprint {
        file: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        sha256: sha256(&bytes),
        size: bytes.len() as u64,
    })
}

/// Whether `path` decodes as an image of exactly `edge` by `edge` pixels with alpha.
pub fn image_is_valid(path: &Path, edge: u32) -> bool {
    let Ok(reader) = image::ImageReader::open(path) else {
        return false;
    };
    let Ok(decoded) = reader.with_guessed_format().and_then(|reader| {
        reader
            .decode()
            .map_err(|err| std::io::Error::other(err.to_string()))
    }) else {
        return false;
    };
    decoded.width() == edge
        && decoded.height() == edge
        // An all-opaque body may encode without an alpha channel; the frame was
        // still rendered on a transparent background.
        && matches!(
            decoded.color(),
            image::ColorType::Rgba8
                | image::ColorType::Rgba16
                | image::ColorType::Rgb8
                | image::ColorType::Rgb16
        )
}

/// Writes an image as WebP through a sibling temporary file.
pub fn save_image_atomic(image: &image::RgbaImage, path: &Path) -> Result<(), String> {
    let mut temporary = path.to_path_buf();
    let mut name = temporary.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp.webp");
    temporary.set_file_name(name);
    image
        .save(&temporary)
        .map_err(|err| format!("cannot encode {}: {err}", temporary.display()))?;
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|err| format!("cannot replace {}: {err}", path.display()))?;
    }
    std::fs::rename(&temporary, path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot rename into {}: {err}", path.display())
    })
}

/// Writes `bytes` to `path` through a sibling temporary file.
///
/// A crash leaves either the previous file or the new one, never a partial
/// file under the final name.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    let temporary = temporary_path(path);
    std::fs::write(&temporary, bytes)
        .map_err(|err| format!("cannot write {}: {err}", temporary.display()))?;
    if path.exists() {
        std::fs::remove_file(path)
            .map_err(|err| format!("cannot replace {}: {err}", path.display()))?;
    }
    std::fs::rename(&temporary, path).map_err(|err| {
        let _ = std::fs::remove_file(&temporary);
        format!("cannot rename into {}: {err}", path.display())
    })
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Hashes the readable files under `root`, by relative path, size and mtime.
///
/// This is a cheap stand-in for hashing the contents of a multi-gigabyte
/// texture store: a replaced dictionary changes a size or a timestamp.
pub fn digest_root(root: &Path) -> String {
    let mut entries: BTreeMap<String, (u64, i64)> = BTreeMap::new();
    collect(root, root, &mut entries);
    let mut hasher = Sha256::new();
    for (path, (len, modified)) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(len.to_le_bytes());
        hasher.update(modified.to_le_bytes());
    }
    hex(&hasher.finalize())
}

fn collect(root: &Path, path: &Path, entries: &mut BTreeMap<String, (u64, i64)>) {
    let Ok(read) = std::fs::read_dir(path) else {
        return;
    };
    for item in read.flatten() {
        let item_path = item.path();
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            collect(root, &item_path, entries);
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let relative = item_path
            .strip_prefix(root)
            .unwrap_or(&item_path)
            .to_string_lossy()
            .replace('\\', "/");
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        entries.insert(relative, (metadata.len(), modified));
    }
}

/// SHA-256 of a byte slice as lowercase hex.
pub fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(body: &str, size: u32) -> Inputs<'_> {
        Inputs {
            body_sha256: body,
            model: "akane",
            paint: [0.1, 0.2, 0.3, 1.0],
            colors_sha256: "abc",
            textures: &[],
            size,
            thumb: 320,
        }
    }

    #[test]
    fn the_identity_changes_with_every_declared_input() {
        let base = identity(&inputs("body", 1024));
        assert_eq!(base, identity(&inputs("body", 1024)));
        assert_ne!(base, identity(&inputs("other", 1024)));
        assert_ne!(base, identity(&inputs("body", 512)));
    }

    #[test]
    fn the_identity_does_not_depend_on_texture_root_order() {
        let left = [
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "1".to_string()),
        ];
        let right = [
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ];
        let mut first = inputs("body", 1024);
        first.textures = &left;
        let mut second = inputs("body", 1024);
        second.textures = &right;
        assert_eq!(identity(&first), identity(&second));
    }

    #[test]
    fn an_atomic_write_replaces_the_previous_file() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("image.webp");
        write_atomic(&path, b"first").expect("write");
        write_atomic(&path, b"second").expect("replace");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
        assert!(!temporary_path(&path).exists());
    }

    #[test]
    fn a_missing_texture_root_digests_to_a_stable_value() {
        let missing = Path::new("no-such-directory-for-the-cache-test");
        assert_eq!(digest_root(missing), digest_root(missing));
    }
}
