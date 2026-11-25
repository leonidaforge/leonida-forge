use std::collections::BTreeMap;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use clap::{ArgGroup, Subcommand};
use lforge_rage9::Status;
use lforge_rage9::resource::{Segment, Storage};
use lforge_rage9::rpf::{self, Index, Origin, Progress, Resource};
use serde_json::{Value, json};

use crate::{extract, metadata, recover, rows};

/// How the contents of an RPF9 archive are obtained, for users who expect a
/// file listing.
const RECOVERY_NOTE: &str = "The table of contents is encrypted and is not read. Entries are zlib \
     streams recovered from the data area; they have no original names or paths.";

const NOTHING_RECOVERED: &str = "No zlib streams were found, so no entries can be listed. This does not mean the archive is empty.";

/// The schema of an `archive info` document. Version 1 is the first version
/// with an explicit identifier; its `kind` values use the corrected names,
/// including `psin` where earlier builds said `pso`.
const INFO_SCHEMA: &str = "leonida-forge.archive-info/1";
/// The schema of an `archive list` document, with the same kind naming.
const LIST_SCHEMA: &str = "leonida-forge.archive-list/1";

/// Resource streams are only listed after they inflated completely.
const TRANSPORT_NOTE: &str = "every stream inflated completely with a valid checksum";

#[derive(Subcommand)]
pub enum Command {
    /// Print archive metadata and a summary of the recovered entries
    Info {
        file: PathBuf,
        /// Neither read nor write the index cache
        #[arg(long)]
        no_cache: bool,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// List recovered entries and unrecovered regions
    List {
        file: PathBuf,
        /// Neither read nor write the index cache
        #[arg(long)]
        no_cache: bool,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the pages and checks of one reconstructed resource
    Resource {
        file: PathBuf,
        /// The resource id, or the id of one of its pages
        #[arg(value_parser = lforge_binary::parse_offset)]
        id: u64,
        /// Neither read nor write the index cache
        #[arg(long)]
        no_cache: bool,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the table of contents and its entries. Processed metadata is
    /// authenticated with a compatible executable before its entries are used
    Metadata {
        file: PathBuf,
        /// List the entries
        #[arg(long)]
        entries: bool,
        /// List at most this many entries
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// A local name table: candidate paths, `hash64:HASH<TAB>name` and
        /// `key32:HASH<TAB>name` mappings, or a `.lut` file. Repeatable.
        /// Defaults to `<archive>.names.txt` next to the archive when it exists.
        /// The built-in LUTs are always applied, and a `rpf9-hash64.lut` or
        /// `rpf9-key32.lut` beside the executable is read as well
        #[arg(long = "name-file", visible_alias = "candidates")]
        candidates: Vec<PathBuf>,
        /// The archive's own path, whose directory is the mount prefix
        #[arg(long, conflicts_with = "mount_prefix", requires = "candidates")]
        archive_path: Option<String>,
        /// The prefix the archive is mounted at, ending in a slash or backslash
        #[arg(long, requires = "candidates")]
        mount_prefix: Option<String>,
        /// Map an extension to a type ID and class: EXT=TYPE[:hash64|key32].
        /// Only rpf=0:hash64 is built in
        #[arg(long = "extension", value_parser = metadata::parse_extension, requires = "candidates")]
        extensions: Vec<metadata::Extension>,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Probe the static cipher and A table with a local executable. The
    /// archive is read only, and no signature is verified
    Probe {
        file: PathBuf,
        /// The executable to recognize the key provider in
        #[arg(long)]
        executable: PathBuf,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Export one native table-of-contents entry, decoded where supported
    Extract {
        file: PathBuf,
        /// Descend into an archive stored in the previous one: `row:N` for a
        /// native RPF9 row, `zip:N` for a ZIP entry. Repeatable
        #[arg(long = "enter", value_name = "SELECTOR")]
        enters: Vec<crate::nested::Selector>,
        /// The row index of the entry, as `archive metadata --entries` lists
        /// it, in the archive reached by the last `--enter`
        #[arg(long)]
        row: u32,
        /// Where to write the entry's contents
        #[arg(long)]
        output: PathBuf,
        /// Replace the output file if it already exists
        #[arg(long)]
        overwrite: bool,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
    },
    /// Inspect the decoded contents of one native row or ZIP entry in a
    /// recognised format, without extracting it to a file
    Inspect {
        file: PathBuf,
        /// Descend into an archive stored in the previous one: `row:N` for a
        /// native RPF9 row, `zip:N` for a ZIP entry. Repeatable
        #[arg(long = "enter", value_name = "SELECTOR")]
        enters: Vec<crate::nested::Selector>,
        /// The row index of the entry in the last archive. Without `--enter`
        /// and `--zip`, row 0 is read; with `--enter`, a missing selection
        /// inspects the entered archive itself
        #[arg(long, conflicts_with = "zip")]
        row: Option<u32>,
        /// The ZIP entry index in the last archive
        #[arg(long, value_name = "INDEX", conflicts_with = "row")]
        zip: Option<usize>,
        /// Inspect the bytes as stored instead of the decoded payload
        #[arg(long)]
        raw: bool,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// Records and entries included in the report
        #[arg(long, default_value_t = crate::inspect::DEFAULT_SAMPLE)]
        sample: usize,
        /// Read every block's storage class instead of the first sample
        #[arg(long)]
        blocks: bool,
        /// Decode every decodable block and report what fails
        #[arg(long)]
        verify: bool,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// List the authenticated native rows of one archive as stable records,
    /// with resolved names, type, extension and readability
    Ls {
        file: PathBuf,
        /// Descend into an archive stored in the previous one before listing
        /// its rows: `row:N` for a native RPF9 row, `zip:N` for a ZIP entry
        #[arg(long = "enter", value_name = "SELECTOR")]
        enters: Vec<crate::nested::Selector>,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A local name table, or a `.lut` file. Defaults to
        /// `<archive>.names.txt` when it exists. The built-in LUTs always apply
        #[arg(long = "name-file", visible_alias = "candidates")]
        candidates: Vec<PathBuf>,
        /// The first row to list
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// The most rows to list
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Search authenticated native rows by name, key, type, extension,
    /// readability or archive, in one archive or a directory of archives
    Search {
        /// An .rpf file or a directory searched recursively for .rpf files
        path: PathBuf,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A local name table, or a `.lut` file. Defaults to
        /// `<archive>.names.txt` when it exists. The built-in LUTs always apply
        #[arg(long = "name-file", visible_alias = "candidates")]
        candidates: Vec<PathBuf>,
        /// A case-insensitive substring of a resolved name
        #[arg(long)]
        name: Option<String>,
        /// A stored hash64 (16 hexadecimal digits) or key32 (8 digits)
        #[arg(long, value_parser = rows::parse_hash)]
        hash: Option<lforge_rage9::rpf::names::Key>,
        /// A type ID
        #[arg(long = "type", value_name = "TYPE")]
        type_id: Option<u8>,
        /// A confirmed extension, without the dot
        #[arg(long)]
        extension: Option<String>,
        /// Whether the payload is readable: true or false
        #[arg(long, value_name = "BOOL", value_parser = clap::value_parser!(bool))]
        readable: Option<bool>,
        /// A case-insensitive substring of an archive's path under the search
        /// root
        #[arg(long)]
        archive: Option<String>,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long, default_value_t = 32)]
        max_depth: usize,
        #[arg(long, default_value_t = 64)]
        max_archives: usize,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Export a deterministic manifest of the native rows of one archive
    Manifest {
        file: PathBuf,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A local name table, or a `.lut` file. Defaults to
        /// `<archive>.names.txt` when it exists. The built-in LUTs always apply
        #[arg(long = "name-file", visible_alias = "candidates")]
        candidates: Vec<PathBuf>,
        /// json (one document) or jsonl (a header, then one row per line)
        #[arg(long, default_value = "json")]
        format: String,
        /// Where to write the manifest. Defaults to standard output
        #[arg(long)]
        output: Option<PathBuf>,
        /// Replace the output file if it already exists
        #[arg(long)]
        overwrite: bool,
    },
    /// Inventory the entries of supported archives as a deterministic,
    /// machine-readable manifest, optionally descending into nested archives
    Inventory {
        /// An archive file, or a directory searched recursively for .rpf and
        /// .zip files
        path: PathBuf,
        /// The executable to recognize the metadata key provider in. Required
        /// only for encrypted metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A local name table, or a `.lut` file. The built-in LUTs always apply
        #[arg(long = "name-file", visible_alias = "candidates")]
        candidates: Vec<PathBuf>,
        /// Enter archives stored inside an archive, recognised from content
        #[arg(long)]
        recursive: bool,
        /// jsonl (a header, then one record per line, then a summary) or json
        /// (one document)
        #[arg(long, value_parser = crate::inventory::OutputFormat::parse, default_value = "jsonl")]
        format: crate::inventory::OutputFormat,
        /// Where to write the inventory. Defaults to standard output
        #[arg(long)]
        output: Option<PathBuf>,
        /// Replace the output file if it already exists
        #[arg(long)]
        overwrite: bool,
        /// Archives in a chain, counting the root
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_depth)]
        max_depth: usize,
        /// Archives opened, roots included
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_archives)]
        max_archives: u64,
        /// Entries recorded, all archives included
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_entries)]
        max_entries: u64,
        /// Largest payload decoded into temporary storage
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_entry_bytes)]
        max_entry_bytes: u64,
        /// Total payload bytes decoded into temporary storage
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_decoded_bytes)]
        max_decoded_bytes: u64,
        /// Temporary storage held on one chain
        #[arg(long, default_value_t = crate::inventory::Limits::default().max_temp_bytes)]
        max_temp_bytes: u64,
        /// Only emit entries whose recognised content format has this id
        #[arg(long = "content-format")]
        content_format: Option<String>,
        /// Only emit entries of this RPF9 type id
        #[arg(long = "type", value_name = "TYPE")]
        type_id: Option<u8>,
        /// Only emit entries whose name or resolved name contains this text
        #[arg(long)]
        name: Option<String>,
        /// Only emit entries with this stored hash64 or key32
        #[arg(long, value_parser = rows::parse_hash)]
        hash: Option<lforge_rage9::rpf::names::Key>,
        /// Only emit entries whose payload is readable: true or false
        #[arg(long, value_name = "BOOL", value_parser = clap::value_parser!(bool))]
        readable: Option<bool>,
        /// Only emit entries stopped at this failure stage
        #[arg(long = "failure-stage")]
        failure_stage: Option<String>,
        /// Only emit entries in an archive nested this many levels under the
        /// root
        #[arg(long)]
        depth: Option<usize>,
    },
    /// List scan-recovery candidates, or export one of them. These are entries
    /// recovered from the data area, not native table-of-contents entries
    #[command(group(
        ArgGroup::new("recover_mode").required(true).args(["list", "id"])
    ))]
    Recover {
        file: PathBuf,
        /// List the recovery candidates
        #[arg(long, conflicts_with_all = ["output", "overwrite"])]
        list: bool,
        /// Export the candidate with this id, its archive offset as
        /// `recover --list` reports it
        #[arg(long, value_parser = lforge_binary::parse_offset, requires = "output")]
        id: Option<u64>,
        /// Where to write the exported candidate
        #[arg(long, requires = "id")]
        output: Option<PathBuf>,
        /// Replace the output file if it already exists
        #[arg(long, requires = "id")]
        overwrite: bool,
        /// Neither read nor write the index cache
        #[arg(long)]
        no_cache: bool,
        /// Print the candidate list as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Info {
            file,
            no_cache,
            json,
        } => info(&file, no_cache, json),
        Command::List {
            file,
            no_cache,
            json,
        } => list(&file, no_cache, json),
        Command::Resource {
            file,
            id,
            no_cache,
            json,
        } => resource(&file, id, no_cache, json),
        Command::Metadata {
            file,
            entries,
            limit,
            candidates,
            archive_path,
            mount_prefix,
            extensions,
            executable,
            json,
        } => metadata::run(
            &file,
            &metadata::Options {
                entries,
                limit,
                candidates,
                archive_path,
                mount_prefix,
                extensions,
                executable,
                json,
            },
        ),
        Command::Extract {
            file,
            enters,
            row,
            output,
            overwrite,
            executable,
        } => {
            let cancel = AtomicBool::new(false);
            let resolved = (!enters.is_empty())
                .then(|| crate::nested::resolve(&file, executable.as_deref(), &enters, &cancel))
                .transpose()?;
            let path = resolved
                .as_ref()
                .map_or(file.as_path(), |r| r.path.as_path());
            extract::run(path, row, &output, overwrite, executable.as_deref())
        }
        Command::Inspect {
            file,
            enters,
            row,
            zip,
            raw,
            executable,
            sample,
            blocks,
            verify,
            json,
        } => crate::inspect::archive(
            &file,
            executable.as_deref(),
            &enters,
            &crate::inspect::Selection { row, zip, raw },
            &crate::inspect::Options {
                sample,
                blocks,
                verify,
                json,
            },
        ),
        Command::Ls {
            file,
            enters,
            executable,
            candidates,
            offset,
            limit,
            json,
        } => {
            let cancel = AtomicBool::new(false);
            let resolved = (!enters.is_empty())
                .then(|| crate::nested::resolve(&file, executable.as_deref(), &enters, &cancel))
                .transpose()?;
            let path = resolved.as_ref().map_or(file, |r| r.path.clone());
            rows::run_ls(rows::LsOptions {
                file: path,
                executable,
                candidates,
                offset,
                limit,
                json,
            })
        }
        Command::Search {
            path,
            executable,
            candidates,
            name,
            hash,
            type_id,
            extension,
            readable,
            archive,
            offset,
            limit,
            max_depth,
            max_archives,
            json,
        } => rows::run_search(rows::SearchOptions {
            path,
            executable,
            candidates,
            name,
            hash,
            type_id,
            extension,
            readable,
            archive,
            offset,
            limit,
            max_depth,
            max_archives,
            json,
        }),
        Command::Manifest {
            file,
            executable,
            candidates,
            format,
            output,
            overwrite,
        } => rows::run_manifest(rows::ManifestOptions {
            file,
            executable,
            candidates,
            format,
            output,
            overwrite,
        }),
        Command::Inventory {
            path,
            executable,
            candidates,
            recursive,
            format,
            output,
            overwrite,
            max_depth,
            max_archives,
            max_entries,
            max_entry_bytes,
            max_decoded_bytes,
            max_temp_bytes,
            content_format,
            type_id,
            name,
            hash,
            readable,
            failure_stage,
            depth,
        } => crate::inventory::run(crate::inventory::Options {
            path,
            executable,
            candidates,
            recursive,
            format,
            output,
            overwrite,
            limits: crate::inventory::Limits {
                max_depth,
                max_archives,
                max_entries,
                max_entry_bytes,
                max_decoded_bytes,
                max_temp_bytes,
            },
            filters: crate::inventory::Filters {
                content_format,
                type_id,
                name,
                hash,
                readable,
                failure_stage,
                depth,
            },
        }),
        Command::Probe {
            file,
            executable,
            json,
        } => crate::probe::run(&file, &executable, json),
        Command::Recover {
            file,
            list,
            id,
            output,
            overwrite,
            no_cache,
            json,
        } => recover::run(recover::Options {
            file,
            list,
            id,
            output,
            overwrite,
            no_cache,
            json,
        }),
    }
}

/// The stable identifier of an entry, page or region: its archive offset.
pub(crate) fn id(offset: u64) -> String {
    format!("0x{offset:010X}")
}

/// Loads the cached index or scans the archive, showing progress on a
/// terminal. Ctrl+C ends a scan without writing a cache file.
pub(crate) fn index(path: &Path, no_cache: bool) -> Result<(Index, Origin), String> {
    let mut source = lforge_binary::Source::open(path)
        .map_err(|err| format!("cannot open {}: {err}", path.display()))?;
    rpf::read_header(&mut source).map_err(|err| format!("{}: {err}", path.display()))?;

    let cache_dir = (!no_cache)
        .then(lforge_core::data_dir)
        .flatten()
        .map(|dir| dir.join("cache").join("rpf"));
    let progress = Progress::default();
    let cancel = AtomicBool::new(false);
    let show_progress = io::stderr().is_terminal();
    let (done, finished) = mpsc::channel::<()>();
    let result = thread::scope(|scope| {
        if show_progress {
            let progress = &progress;
            scope.spawn(move || {
                while finished.recv_timeout(Duration::from_millis(200)).is_err() {
                    if let Some(fraction) = progress.fraction() {
                        eprint!("\rindexing {:5.1}%", fraction * 100.0);
                    }
                }
            });
        }
        let result = rpf::open(path, cache_dir.as_deref(), &progress, &cancel);
        drop(done);
        result
    });
    if show_progress && progress.total() > 0 && !cancel.load(Ordering::Relaxed) {
        eprint!("\r{:16}\r", "");
    }
    result.map_err(|err| format!("cannot index {}: {err}", path.display()))
}

fn counts(index: &Index) -> BTreeMap<(&'static str, &'static str), (u64, u64)> {
    let mut counts = BTreeMap::new();
    for entry in &index.entries {
        let count = counts
            .entry((entry.kind.name(), entry.status.name()))
            .or_insert((0, 0));
        count.0 += 1;
        count.1 += entry.len;
    }
    counts
}

#[derive(Default)]
struct ResourceSummary {
    complete: u64,
    partial: u64,
    unverified: u64,
    system_pages: u64,
    graphics_pages: u64,
    system_len: u64,
    graphics_len: u64,
}

fn resource_summary(index: &Index) -> ResourceSummary {
    let mut summary = ResourceSummary::default();
    for resource in &index.resources {
        match resource.status() {
            Status::Complete => summary.complete += 1,
            Status::Partial => summary.partial += 1,
            Status::Unverified => summary.unverified += 1,
        }
        let layout = &resource.layout;
        summary.system_pages += layout.segment_pages(Segment::System).count() as u64;
        summary.graphics_pages += layout.segment_pages(Segment::Graphics).count() as u64;
        summary.system_len += layout.segment_len(Segment::System);
        summary.graphics_len += layout.segment_len(Segment::Graphics);
    }
    summary
}

fn info(path: &Path, no_cache: bool, json: bool) -> Result<(), String> {
    let (index, origin) = index(path, no_cache)?;
    let header = &index.header;
    let percent = |part: u64| {
        if index.data_len() == 0 {
            0.0
        } else {
            part as f64 * 100.0 / index.data_len() as f64
        }
    };
    let counts = counts(&index);
    let resources = resource_summary(&index);
    let origin = match origin {
        Origin::Cache => "cache",
        Origin::Scan => "scan",
    };

    if json {
        let info = json!({
            "schema": INFO_SCHEMA,
            "path": std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()).to_string_lossy(),
            "format": "RPF9",
            "size": index.archive_len,
            "toc_end": index.header.toc_end(),
            "data_start": header.data_start(),
            "header": lforge_binary::hex_bytes(header.bytes()),
            "table_of_contents": "encrypted, not read",
            "index_source": origin,
            "streams": index.streams.len(),
            "entries": index.entries.len(),
            "recovered_bytes": index.recovered_len(),
            "unrecovered_regions": index.regions.len(),
            "unrecovered_bytes": index.unrecovered_len(),
            "resources": {
                "count": index.resources.len(),
                "complete": resources.complete,
                "partial": resources.partial,
                "unverified": resources.unverified,
                "system_pages": resources.system_pages,
                "graphics_pages": resources.graphics_pages,
                "system_size": resources.system_len,
                "graphics_size": resources.graphics_len,
            },
            "by_kind": counts.iter().map(|((kind, status), (count, bytes))| json!({
                "kind": kind,
                "status": status,
                "count": count,
                "size": bytes,
            })).collect::<Vec<Value>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&info).expect("JSON value")
        );
        return Ok(());
    }

    println!("format:      RPF9");
    println!(
        "size:        {} bytes ({:#x})",
        index.archive_len, index.archive_len
    );
    println!("toc end:     {:#x}", header.toc_end());
    println!("data start:  {:#x}", header.data_start());
    for (row, bytes) in header.bytes().chunks(16).enumerate() {
        let label = if row == 0 { "header:" } else { "" };
        println!("{label:13}{}", lforge_binary::hex_bytes(bytes));
    }
    println!("index:       from {origin}");
    println!();
    println!("{RECOVERY_NOTE}");
    if index.entries.is_empty() {
        println!("{NOTHING_RECOVERED}");
    }
    println!();
    println!(
        "entries:     {} from {} streams, {:.1}% of the data area",
        index.entries.len(),
        index.streams.len(),
        percent(index.recovered_len())
    );
    println!(
        "unrecovered: {} regions, {} bytes ({:.1}%)",
        index.regions.len(),
        index.unrecovered_len(),
        percent(index.unrecovered_len())
    );
    if !index.resources.is_empty() {
        println!(
            "resources:   {} ({} complete, {} partial, {} unverified)",
            index.resources.len(),
            resources.complete,
            resources.partial,
            resources.unverified
        );
        println!(
            "             system {} bytes in {} pages, graphics {} bytes in {} pages",
            resources.system_len,
            resources.system_pages,
            resources.graphics_len,
            resources.graphics_pages
        );
    }
    if !counts.is_empty() {
        println!();
        println!(
            "{:<10} {:<11} {:>8} {:>14}",
            "kind", "status", "count", "bytes"
        );
        for ((kind, status), (count, bytes)) in &counts {
            println!("{kind:<10} {status:<11} {count:>8} {bytes:>14}");
        }
    }
    Ok(())
}

fn list(path: &Path, no_cache: bool, json: bool) -> Result<(), String> {
    let (index, _) = index(path, no_cache)?;
    let out = io::stdout().lock();
    let mut out = BufWriter::new(out);
    let result = if json {
        list_json(&index, &mut out)
    } else {
        list_text(&index, &mut out)
    };
    result
        .and_then(|()| out.flush())
        .or_else(ignore_broken_pipe)
        .map_err(|err| format!("cannot write output: {err}"))
}

fn resource_json(index: &Index, resource: &Resource) -> Value {
    let layout = &resource.layout;
    let pages: Vec<Value> = index
        .resource_pages(resource)
        .map(|(page, streams)| {
            let offset = match page.storage {
                Storage::Raw { offset } => offset,
                Storage::Streams => streams.first().map_or(resource.offset, |s| s.offset),
            };
            let stored: u64 = match page.storage {
                Storage::Raw { .. } => page.len,
                Storage::Streams => streams.iter().map(|s| u64::from(s.stored_len)).sum(),
            };
            json!({
                "id": id(offset),
                "offset": offset,
                "segment": page.segment.name(),
                "size": page.len,
                "storage": page.storage.name(),
                "compressed_size": stored,
                "streams": page.stream_count,
            })
        })
        .collect();
    let pointers = layout.pointers;
    json!({
        "status": resource.status().name(),
        "transport": TRANSPORT_NOTE,
        "system_size": layout.segment_len(Segment::System),
        "graphics_size": layout.segment_len(Segment::Graphics),
        "page_map": match layout.page_map {
            Ok(map) => json!({
                "offset": map.offset,
                "system_pages": map.system_pages,
                "graphics_pages": map.graphics_pages,
            }),
            Err(_) => Value::Null,
        },
        "tag": layout.tag,
        "pages": pages,
        "pointers": {
            "system": pointers.system,
            "graphics": pointers.graphics,
            "system_outside": pointers.system_outside,
            "graphics_outside": pointers.graphics_outside,
            "all_checked": pointers.checked,
        },
        "issues": layout.issues().iter().map(|issue| issue.describe()).collect::<Vec<_>>(),
    })
}

fn list_json(index: &Index, out: &mut impl Write) -> io::Result<()> {
    let entries: Vec<Value> = index
        .entries
        .iter()
        .map(|entry| {
            let mut value = json!({
                "id": id(entry.offset),
                "offset": entry.offset,
                "kind": entry.kind.name(),
                "extension": entry.kind.extension(),
                "extension_synthetic": entry.kind.extension_is_synthetic(),
                "status": entry.status.name(),
                "size": entry.len,
                "compressed_size": entry.stored_len,
                "streams": entry.stream_count(),
            });
            if let Some(resource) = index.resource_at(entry.offset) {
                value["resource"] = resource_json(index, resource);
            }
            value
        })
        .collect();
    let regions: Vec<Value> = index
        .regions
        .iter()
        .map(|region| {
            json!({
                "id": id(region.offset),
                "offset": region.offset,
                "size": region.len,
            })
        })
        .collect();
    let listing = json!({
        "schema": LIST_SCHEMA,
        "note": if index.entries.is_empty() {
            format!("{RECOVERY_NOTE} {NOTHING_RECOVERED}")
        } else {
            RECOVERY_NOTE.to_string()
        },
        "table_of_contents": "encrypted, not read",
        "names": "none recovered; ids are archive offsets",
        "entries": entries,
        "unrecovered_regions": regions,
    });
    serde_json::to_writer_pretty(&mut *out, &listing)?;
    writeln!(out)
}

fn list_text(index: &Index, out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{RECOVERY_NOTE}")?;
    if index.entries.is_empty() {
        writeln!(out, "{NOTHING_RECOVERED}")?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "{:<12} {:<10} {:<11} {:>12} {:>12} {:>7}",
        "id", "kind", "status", "size", "compressed", "streams"
    )?;
    for entry in &index.entries {
        writeln!(
            out,
            "{:<12} {:<10} {:<11} {:>12} {:>12} {:>7}",
            id(entry.offset),
            entry.kind.name(),
            entry.status.name(),
            entry.len,
            entry.stored_len,
            entry.stream_count()
        )?;
    }
    for region in &index.regions {
        writeln!(
            out,
            "{:<12} {:<10} {:<11} {:>12} {:>12} {:>7}",
            id(region.offset),
            "-",
            "unrecovered",
            region.len,
            "-",
            "-"
        )?;
    }
    Ok(())
}

fn resource(path: &Path, offset: u64, no_cache: bool, json: bool) -> Result<(), String> {
    let (index, _) = index(path, no_cache)?;
    let resource = index
        .resource_at(offset)
        .or_else(|| index.page_at(offset).map(|(resource, ..)| resource))
        .ok_or_else(|| format!("no resource or resource page has the id {}", id(offset)))?;
    let report = resource_json(&index, resource);
    if json {
        let mut value = json!({ "id": id(resource.offset), "offset": resource.offset });
        value
            .as_object_mut()
            .expect("object")
            .extend(report.as_object().expect("object").clone());
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON value")
        );
        return Ok(());
    }

    let layout = &resource.layout;
    let segment = |segment: Segment| {
        let pages = layout.segment_pages(segment).count();
        format!(
            "{} bytes in {pages} {}",
            layout.segment_len(segment),
            if pages == 1 { "page" } else { "pages" }
        )
    };
    println!("resource:    {}", id(resource.offset));
    println!("status:      {}", resource.status().name());
    println!("transport:   {TRANSPORT_NOTE}");
    println!("system:      {}", segment(Segment::System));
    println!("graphics:    {}", segment(Segment::Graphics));
    match layout.page_map {
        Ok(map) => println!(
            "page map:    at {:#x}, declares {} system and {} graphics pages",
            map.offset, map.system_pages, map.graphics_pages
        ),
        Err(err) => println!("page map:    {}", err.describe()),
    }
    if let Some(tag) = layout.tag {
        println!("tag:         0DRP {tag:#04x}");
    }
    let pointers = layout.pointers;
    println!(
        "pointers:    {} system, {} graphics; {} and {} outside{}",
        pointers.system,
        pointers.graphics,
        pointers.system_outside,
        pointers.graphics_outside,
        if pointers.checked {
            ""
        } else {
            " (not all checked)"
        }
    );
    println!();
    println!(
        "{:<12} {:<9} {:>12} {:>12} {:>7}",
        "page", "segment", "size", "compressed", "streams"
    );
    for (page, streams) in index.resource_pages(resource) {
        let (offset, stored) = match page.storage {
            Storage::Raw { offset } => (offset, page.len),
            Storage::Streams => (
                streams.first().map_or(resource.offset, |s| s.offset),
                streams.iter().map(|s| u64::from(s.stored_len)).sum(),
            ),
        };
        println!(
            "{:<12} {:<9} {:>12} {:>12} {:>7}",
            id(offset),
            page.segment.name(),
            page.len,
            stored,
            page.stream_count
        );
    }
    if let Some(tail) = layout.tail {
        println!();
        println!("warning: {}", tail.describe());
    }
    let issues = layout.issues();
    if !issues.is_empty() {
        println!();
        for issue in issues {
            println!("warning: {}", issue.describe());
        }
    }
    Ok(())
}

/// Piping into `head` closes stdout early; that is not a failure.
pub(crate) fn ignore_broken_pipe(err: io::Error) -> io::Result<()> {
    if err.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(err)
    }
}
