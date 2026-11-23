use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, Subcommand, ValueEnum};
use lforge_binary::{Endian, Source, Utf8Preview};
use serde_json::{Value, json};

/// Bytes of the file signature shown by `info`.
const SIGNATURE_LEN: usize = 16;
/// Bytes decoded by `interpret`; enough for every type and a text preview.
const INTERPRET_LEN: usize = 32;
/// Bytes read per step by `dump`.
const DUMP_CHUNK: usize = 64 * 1024;

#[derive(Subcommand)]
pub enum Command {
    /// Print file information, signature bytes and SHA-256
    Info {
        file: PathBuf,
        /// Skip the SHA-256 checksum, which reads the whole file
        #[arg(long)]
        no_hash: bool,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Print a hex dump of a byte range
    Dump {
        file: PathBuf,
        /// Start offset, decimal or 0x-prefixed hex
        #[arg(long, default_value = "0", value_parser = lforge_binary::parse_offset)]
        offset: u64,
        /// Number of bytes, decimal or 0x-prefixed hex
        #[arg(long, default_value = "256", value_parser = lforge_binary::parse_offset)]
        length: u64,
        /// Bytes per row
        #[arg(long, default_value = "16", value_parser = ["8", "16", "32"])]
        width: String,
    },
    /// Print the offsets of all matches of a byte pattern
    Search {
        file: PathBuf,
        #[command(flatten)]
        pattern: PatternArgs,
        /// Offset to start searching from
        #[arg(long, default_value = "0", value_parser = lforge_binary::parse_offset)]
        offset: u64,
        /// Stop after this many matches
        #[arg(long)]
        limit: Option<u64>,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Interpret the bytes at an offset as primitive values
    Interpret {
        file: PathBuf,
        /// Offset, decimal or 0x-prefixed hex
        #[arg(long, default_value = "0", value_parser = lforge_binary::parse_offset)]
        offset: u64,
        #[arg(long, value_enum, default_value_t = EndianArg::Little)]
        endian: EndianArg,
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Clap treats a field spelled `Vec<_>` as a list of values; the alias keeps
/// the parsed pattern a single value.
type Bytes = Vec<u8>;

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct PatternArgs {
    /// Hex bytes, e.g. "52 50 46 37"
    #[arg(long, value_parser = lforge_binary::parse_hex_pattern)]
    hex: Option<Bytes>,
    /// Text, searched for as UTF-8 bytes
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    text: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum EndianArg {
    Little,
    Big,
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Info {
            file,
            no_hash,
            json,
        } => info(&file, !no_hash, json),
        Command::Dump {
            file,
            offset,
            length,
            width,
        } => dump(
            &file,
            offset,
            length,
            width.parse().expect("validated width"),
        ),
        Command::Search {
            file,
            pattern,
            offset,
            limit,
            json,
        } => {
            let pattern = match (pattern.hex, pattern.text) {
                (Some(bytes), _) => bytes,
                (None, Some(text)) => text.into_bytes(),
                (None, None) => unreachable!("clap requires one pattern"),
            };
            search(&file, &pattern, offset, limit, json)
        }
        Command::Interpret {
            file,
            offset,
            endian,
            json,
        } => {
            let endian = match endian {
                EndianArg::Little => Endian::Little,
                EndianArg::Big => Endian::Big,
            };
            interpret(&file, offset, endian, json)
        }
    }
}

fn open(path: &Path) -> Result<Source, String> {
    Source::open(path).map_err(|err| format!("cannot open {}: {err}", path.display()))
}

fn read_error(path: &Path) -> impl Fn(io::Error) -> String {
    move |err| format!("cannot read {}: {err}", path.display())
}

fn info(path: &Path, hash: bool, json: bool) -> Result<(), String> {
    let mut source = open(path)?;
    let modified = path
        .metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .map(|time| DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Secs, true));
    let signature =
        lforge_binary::read_at(&mut source, 0, SIGNATURE_LEN).map_err(read_error(path))?;
    let sha256 = if hash {
        let digest = lforge_binary::sha256(&mut source, &AtomicBool::new(false))
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        Some(lforge_binary::hex_digest(&digest))
    } else {
        None
    };
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let full_path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let signature = lforge_binary::hex_bytes(&signature);

    if json {
        let info = json!({
            "name": name,
            "path": full_path.to_string_lossy(),
            "size": source.len(),
            "modified": modified,
            "signature": signature,
            "sha256": sha256,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&info).expect("JSON value")
        );
    } else {
        println!("name:      {name}");
        println!("path:      {}", full_path.display());
        println!("size:      {} bytes ({:#x})", source.len(), source.len());
        println!("modified:  {}", modified.as_deref().unwrap_or("unknown"));
        println!("signature: {signature}");
        if let Some(sha256) = sha256 {
            println!("sha256:    {sha256}");
        }
    }
    Ok(())
}

fn dump(path: &Path, offset: u64, length: u64, width: usize) -> Result<(), String> {
    let mut source = open(path)?;
    let len = source.len();
    if offset > len {
        return Err(format!(
            "offset {offset:#x} is beyond the end of the file ({len:#x} bytes)"
        ));
    }
    let end = offset.saturating_add(length).min(len);
    // Wide enough for the largest offset in the file, and at least 8 digits.
    let digits = (len.max(1) - 1)
        .checked_ilog2()
        .map_or(1, |bits| bits / 4 + 1)
        .max(8) as usize;

    let mut out = BufWriter::new(io::stdout().lock());
    let mut at = offset;
    while at < end {
        let chunk = usize::try_from(end - at).map_or(DUMP_CHUNK, |rest| rest.min(DUMP_CHUNK));
        let bytes = lforge_binary::read_at(&mut source, at, chunk).map_err(read_error(path))?;
        for row in bytes.chunks(width) {
            let hex = lforge_binary::hex_bytes(row);
            let ascii: String = row.iter().map(|b| lforge_binary::ascii_char(*b)).collect();
            writeln!(out, "{at:0digits$X}  {hex:<0$}  |{ascii}|", width * 3 - 1)
                .map_err(write_error)?;
            at += row.len() as u64;
        }
    }
    out.flush().map_err(write_error)
}

fn write_error(err: io::Error) -> String {
    format!("cannot write output: {err}")
}

fn search(
    path: &Path,
    pattern: &[u8],
    offset: u64,
    limit: Option<u64>,
    json: bool,
) -> Result<(), String> {
    let mut source = open(path)?;
    let cancel = AtomicBool::new(false);
    let mut out = BufWriter::new(io::stdout().lock());
    // Matches are written as they are found, so memory stays bounded.
    if json {
        let pattern = json!(lforge_binary::hex_bytes(pattern));
        write!(out, "{{\n  \"pattern\": {pattern},\n  \"matches\": [").map_err(write_error)?;
    }
    let mut count = 0u64;
    let mut from = offset;
    while limit.is_none_or(|limit| count < limit) {
        let found = lforge_binary::find_next(&mut source, pattern, from, &cancel)
            .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
        let Some(at) = found else {
            break;
        };
        if json {
            let separator = if count == 0 { "" } else { "," };
            write!(out, "{separator}\n    {at}").map_err(write_error)?;
        } else {
            writeln!(out, "{at:#010x}").map_err(write_error)?;
        }
        count += 1;
        from = at + 1;
    }
    if json {
        let indent = if count == 0 { "" } else { "\n  " };
        writeln!(out, "{indent}]\n}}").map_err(write_error)?;
    }
    out.flush().map_err(write_error)
}

fn interpret(path: &Path, offset: u64, endian: Endian, json: bool) -> Result<(), String> {
    let mut source = open(path)?;
    let bytes =
        lforge_binary::read_at(&mut source, offset, INTERPRET_LEN).map_err(read_error(path))?;
    let values = lforge_binary::interpret(&bytes, endian);
    let ascii: String = bytes
        .iter()
        .map(|b| lforge_binary::ascii_char(*b))
        .collect();
    let utf8 = lforge_binary::utf8_preview(&bytes);
    let endian_name = match endian {
        Endian::Little => "little",
        Endian::Big => "big",
    };

    if json {
        // JSON has no NaN or infinities, so those are written as strings.
        let f32_value = match values.f32 {
            Some(v) if v.is_finite() => json!(v),
            Some(v) => json!(lforge_binary::format_f32(v)),
            None => Value::Null,
        };
        let f64_value = match values.f64 {
            Some(v) if v.is_finite() => json!(v),
            Some(v) => json!(lforge_binary::format_f64(v)),
            None => Value::Null,
        };
        let utf8 = match utf8 {
            Utf8Preview::Text(text) => json!({ "text": text, "invalid_at": null }),
            Utf8Preview::Invalid { text, offset } => {
                json!({ "text": text, "invalid_at": offset })
            }
        };
        let output = json!({
            "offset": offset,
            "endian": endian_name,
            "bytes": lforge_binary::hex_bytes(&bytes),
            "uint8": values.u8,
            "int8": values.i8,
            "uint16": values.u16,
            "int16": values.i16,
            "uint32": values.u32,
            "int32": values.i32,
            "uint64": values.u64,
            "int64": values.i64,
            "float32": f32_value,
            "float64": f64_value,
            "ascii": ascii,
            "utf8": utf8,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("JSON value")
        );
        return Ok(());
    }

    let unavailable = || "unavailable".to_string();
    let int = |decimal: Option<String>, hex: Option<String>| match (decimal, hex) {
        (Some(decimal), Some(hex)) => format!("{decimal:<22} {hex}"),
        _ => unavailable(),
    };
    println!("offset   {offset:#x} ({offset})");
    println!("endian   {endian_name}");
    println!("bytes    {}", lforge_binary::hex_bytes(&bytes));
    let rows = [
        (
            "uint8",
            int(
                values.u8.map(|v| v.to_string()),
                values.u8.map(|v| format!("{v:#04x}")),
            ),
        ),
        (
            "int8",
            values.i8.map_or_else(unavailable, |v| v.to_string()),
        ),
        (
            "uint16",
            int(
                values.u16.map(|v| v.to_string()),
                values.u16.map(|v| format!("{v:#06x}")),
            ),
        ),
        (
            "int16",
            values.i16.map_or_else(unavailable, |v| v.to_string()),
        ),
        (
            "uint32",
            int(
                values.u32.map(|v| v.to_string()),
                values.u32.map(|v| format!("{v:#010x}")),
            ),
        ),
        (
            "int32",
            values.i32.map_or_else(unavailable, |v| v.to_string()),
        ),
        (
            "uint64",
            int(
                values.u64.map(|v| v.to_string()),
                values.u64.map(|v| format!("{v:#018x}")),
            ),
        ),
        (
            "int64",
            values.i64.map_or_else(unavailable, |v| v.to_string()),
        ),
        (
            "float32",
            values
                .f32
                .map_or_else(unavailable, lforge_binary::format_f32),
        ),
        (
            "float64",
            values
                .f64
                .map_or_else(unavailable, lforge_binary::format_f64),
        ),
        ("ascii", ascii),
        (
            "utf8",
            match utf8 {
                Utf8Preview::Text(text) => text,
                Utf8Preview::Invalid { text, offset } => {
                    format!("{text} (invalid byte at +{offset})")
                }
            },
        ),
    ];
    for (name, value) in rows {
        println!("{name:<8} {value}");
    }
    Ok(())
}
