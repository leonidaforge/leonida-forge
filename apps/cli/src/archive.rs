use std::collections::BTreeMap;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use clap::Subcommand;
use lforge_rage9::Status;
use lforge_rage9::resource::Segment;
use lforge_rage9::rpf::{self, Index, Origin, Progress, Resource};
use serde_json::{Value, json};

/// How the contents of an RPF9 archive are obtained, for users who expect a
/// file listing.
const RECOVERY_NOTE: &str = "The table of contents is encrypted and is not read. Entries are zlib \
     streams recovered from the data area; they have no original names or paths.";

const NOTHING_RECOVERED: &str = "No zlib streams were found, so no entries can be listed. This does not mean the archive is empty.";

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
    }
}

/// The stable identifier of an entry, page or region: its archive offset.
fn id(offset: u64) -> String {
    format!("0x{offset:010X}")
}

/// Loads the cached index or scans the archive, showing progress on a
/// terminal. Ctrl+C ends a scan without writing a cache file.
fn index(path: &Path, no_cache: bool) -> Result<(Index, Origin), String> {
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
            json!({
                "id": id(streams[0].offset),
                "offset": streams[0].offset,
                "segment": page.segment.name(),
                "size": page.len,
                "compressed_size": streams.iter().map(|s| u64::from(s.stored_len)).sum::<u64>(),
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
        let stored: u64 = streams.iter().map(|s| u64::from(s.stored_len)).sum();
        println!(
            "{:<12} {:<9} {:>12} {:>12} {:>7}",
            id(streams[0].offset),
            page.segment.name(),
            page.len,
            stored,
            page.stream_count
        );
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
fn ignore_broken_pipe(err: io::Error) -> io::Result<()> {
    if err.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(err)
    }
}
