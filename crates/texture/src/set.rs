//! A bounded index of RDS5 stores below one directory.
//!
//! Scanning reads only the container header, the ETPF descriptor count and the
//! key table. The full block table is parsed lazily when a texture is first
//! decoded, so opening a directory of large stores does not pay for every
//! block.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lforge_binary::Source;

use super::{Error, Store};

const MAX_STORES: usize = 512;
const MAX_DEPTH: usize = 8;
const MAX_DESCRIPTORS: usize = 4_000_000;
const HEADER_LEN: u64 = 0x10;
const RECORD_LEN: u64 = 8;
const ETPF_HEADER_LEN: u64 = 0x10;

/// One directory's `.ttpf` stores, with exact-key lookup and lazy decoding.
#[derive(Debug)]
pub struct StoreSet {
    stores: Vec<StoreEntry>,
    paths: Vec<PathBuf>,
    by_key: HashMap<u64, Vec<(u32, u32)>>,
}

#[derive(Debug)]
struct StoreEntry {
    path: PathBuf,
    keys: Vec<u64>,
    count: usize,
    opened: Mutex<Option<Arc<Store>>>,
}

impl StoreSet {
    /// Scans `root` recursively for `.ttpf` stores. Only headers, descriptor
    /// counts and keys are read.
    pub fn scan(root: &Path) -> Result<Self, Error> {
        let mut candidates = Vec::new();
        collect(root, 0, &mut candidates)?;
        candidates.sort();
        candidates.truncate(MAX_STORES);
        let mut stores = Vec::with_capacity(candidates.len());
        let mut paths = Vec::with_capacity(candidates.len());
        for path in candidates {
            match scan_keys(&path) {
                Ok((keys, count)) => {
                    paths.push(path.clone());
                    stores.push(StoreEntry {
                        path,
                        keys,
                        count,
                        opened: Mutex::new(None),
                    });
                }
                Err(err) => {
                    log::warn!("skipping texture store {}: {err}", path.display());
                }
            }
        }
        let mut by_key: HashMap<u64, Vec<(u32, u32)>> = HashMap::new();
        for (store_index, store) in stores.iter().enumerate() {
            for (texture_index, &key) in store.keys.iter().enumerate() {
                if key != 0 {
                    by_key
                        .entry(key)
                        .or_default()
                        .push((store_index as u32, texture_index as u32));
                }
            }
        }
        Ok(Self {
            stores,
            paths,
            by_key,
        })
    }

    pub fn len(&self) -> usize {
        self.stores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    pub fn path(&self, index: usize) -> Option<&Path> {
        self.paths.get(index).map(PathBuf::as_path)
    }

    /// Every descriptor whose 8-byte key equals `key`, as
    /// `(store index, texture index)`. The caller decides whether zero, one or
    /// several candidates are acceptable.
    pub fn find(&self, key: u64) -> Vec<(usize, u32)> {
        self.by_key
            .get(&key)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(store, texture)| (*store as usize, *texture))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn texture_count(&self) -> usize {
        self.stores.iter().map(|store| store.count).sum()
    }

    /// Opens (or reuses) the full store needed for a decode.
    pub fn open(&self, index: usize) -> Result<Arc<Store>, Error> {
        let entry = self
            .stores
            .get(index)
            .ok_or_else(|| Error::Invalid("the texture store index is stale".into()))?;
        {
            let opened = entry.opened.lock().unwrap_or_else(|err| err.into_inner());
            if let Some(store) = opened.as_ref() {
                return Ok(store.clone());
            }
        }
        let source = Source::open(&entry.path)?;
        let store = Arc::new(Store::open(source)?);
        let mut opened = entry.opened.lock().unwrap_or_else(|err| err.into_inner());
        *opened = Some(store.clone());
        Ok(store)
    }

    /// Reconstructs one source level through the lazily opened store.
    pub fn level(
        &self,
        store: usize,
        texture: u32,
        level: u32,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<super::SourceLevel, Error> {
        self.open(store)?.level(texture, level, cancel)
    }
}

fn scan_keys(path: &Path) -> Result<(Vec<u64>, usize), Error> {
    let mut source = Source::open(path)?;
    let len = source.len();
    let mut header = [0u8; 16];
    source.read_exact(&mut header)?;
    if &header[..4] != b"RDS5" {
        return Err(Error::NotRds5);
    }
    let records = u32::from_le_bytes(header[4..8].try_into().expect("four bytes")) as usize;
    if records == 0 || records > MAX_DESCRIPTORS {
        return Err(Error::Invalid(format!(
            "the RDS5 record count {records} is outside the limit"
        )));
    }
    let record_end = HEADER_LEN
        .checked_add(records as u64 * RECORD_LEN)
        .ok_or_else(|| Error::Invalid("the RDS5 record array overflows".into()))?;
    let etpf = record_end.next_multiple_of(0x100);
    if etpf
        .checked_add(ETPF_HEADER_LEN)
        .is_none_or(|end| end > len)
    {
        return Err(Error::Invalid("the ETPF block is outside the store".into()));
    }
    source.seek(SeekFrom::Start(etpf))?;
    let mut chunk = [0u8; 16];
    source.read_exact(&mut chunk)?;
    if &chunk[..4] != b"ETPF" {
        return Err(Error::Invalid("the store has no ETPF block".into()));
    }
    let count = u32::from_le_bytes(chunk[8..12].try_into().expect("four bytes")) as usize;
    if count > MAX_DESCRIPTORS {
        return Err(Error::Invalid(format!(
            "the ETPF descriptor count {count} is outside the limit"
        )));
    }
    let table_len = count
        .checked_mul(16)
        .ok_or_else(|| Error::Invalid("the ETPF table size overflows".into()))?;
    let keys_at = etpf
        .checked_add(ETPF_HEADER_LEN)
        .and_then(|at| at.checked_add(table_len as u64))
        .ok_or_else(|| Error::Invalid("the ETPF key table overflows".into()))?;
    let key_len = count
        .checked_mul(8)
        .ok_or_else(|| Error::Invalid("the ETPF key table size overflows".into()))?;
    if keys_at
        .checked_add(key_len as u64)
        .is_none_or(|end| end > len)
    {
        return Err(Error::Invalid(
            "the ETPF key table is outside the store".into(),
        ));
    }
    source.seek(SeekFrom::Start(keys_at))?;
    let mut raw = vec![0u8; key_len];
    source.read_exact(&mut raw)?;
    let keys = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|key| u64::from_le_bytes(*key))
        .collect();
    Ok((keys, count))
}

fn collect(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), Error> {
    if depth > MAX_DEPTH || out.len() >= MAX_STORES {
        return Ok(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if depth > 0 => {
            log::debug!("skipping texture store directory {}: {err}", dir.display());
            return Ok(());
        }
        Err(err) => return Err(Error::Io(err)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect(&path, depth + 1, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("ttpf"))
        {
            out.push(path);
            if out.len() >= MAX_STORES {
                return Ok(());
            }
        }
    }
    Ok(())
}
