# Leonida Forge

**Open-source GTA VI research and modding toolkit.**

Leonida Forge is a community-driven project dedicated to researching GTA VI's file formats and scripting systems, and building tools to explore, analyze, and eventually modify them.

The project aims to provide a native desktop application and CLI featuring archive exploration, script decompilation, native function research, asset conversion, and future Blender integration.

Our goal is to make GTA VI modding more accessible through open research, shared knowledge, and reliable tooling.

## Building

The desktop application builds on Windows 11 x64 only. The CLI also builds on
Linux x64; the Alpha workflow builds, tests and packages both platforms and
publishes them in one pre-release, with `lforge` and its checksum.

Requirements for the desktop application:

- [rustup](https://rustup.rs). `rust-toolchain.toml` pins the toolchain, and rustup installs it on first use.
- Visual Studio Build Tools with the "Desktop development with C++" workload and a Windows SDK. GPUI needs the SDK's resource compiler.
- A GPU with Direct3D 12 support for the 3D viewport.

The first build fetches GPUI from the Zed repository, which takes a few minutes.

```sh
cargo run -p lforge-desktop    # desktop application
cargo run -p lforge-cli -- info --json
cargo test --workspace
```

The CLI alone has no Windows-only dependency:

```sh
cargo build --release -p lforge-cli
```

The desktop executable is `leonida-forge.exe` and the CLI is `lforge.exe`.
The desktop app stores its settings in `%APPDATA%\Leonida Forge\settings.json`.
Debug builds have a **Tools > Renderer Demo** window for the 3D renderer.
Set `WGPU_BACKEND` (for example `vulkan`) to run it on a backend other than Direct3D 12.
Set `RUST_LOG=warn` to see log output from debug builds. Release builds have no console.

## Binary Inspector

Double-click a file the explorer cannot otherwise open, or right-click any file and choose **Open in Binary Inspector**.
Files inside archives are extracted to a temporary file first, up to 512 MB.

The CLI exposes the same operations on plain files:

```sh
lforge binary info example.bin --json          # size, signature bytes, SHA-256
lforge binary dump example.bin --offset 0x10 --length 128
lforge binary search example.bin --hex "52 50 46 37"
lforge binary search example.bin --text example --json
lforge binary interpret example.bin --offset 0x10 --endian big --json
lforge binary inspect example.bin --json       # recognised format and its structure
lforge binary inspect texture.rds --texture 3 --output texture.bin
```

Offsets accept decimal or `0x` hexadecimal. Exit codes: 0 on success, 1 when a command fails, 2 for invalid usage.

A format is recognised from the file's first bytes, never from its extension, and the inspector shows what was recognised next to the signature. The CLI and the desktop Binary Inspector use the same recogniser and parser in `lforge-core`, so a format means the same thing in both. `binary inspect` reports the recognised format, its parsed structure, the byte ranges it read and the ranges it left uninterpreted. `--sample` bounds how many records and entries are listed, `--blocks` reads every block's storage selector instead of the first few, and `--verify` inflates every zlib block and reports what failed.

Known formats are the RDS5 container, whose header, record array, ETPF chunk extent, block catalogue, block storage classes and per-element descriptors are parsed, and whose first element's byte chain is reconstructed in the Binary Inspector; the RBF0 document, whose header, object tree, name dictionary, field names, attributes and text nodes are parsed from its token stream; the GFx version-42 container, whose header, extent, frame fields and tag walk are parsed while tag bodies stay opaque; PSIN, whose section walk, `LSCH` and `PMAP` families, block and section tables and `CHKS` checksum are parsed; EDUP, whose entry framing and opaque trailing blob are parsed; ADAT, whose header, per-stream tables, chunk records and the 2,048-byte packet framing of its `0x0B` streams are walked; KB2j and KB2n, whose header, frame index and per-frame audio record framing are walked; and RPF9, which the archive commands read. A structural parse does not imply a semantic decode: PSIN gives no tag or field a meaning, EDUP compares no key unless a store set is supplied, ADAT names no codec and decodes no audio, and KB2 decodes no frame. RDS5 reconstruction produces bytes, not an image. No payload bytes are printed: RBF0 names and text values are reported as lengths and SHA-256 digests only, and EDUP entry fields are reported as counts. A token stream, tag walk or section walk that breaks its grammar stops the parse and reports the offset where it stopped. A structure that breaks the documented contract is reported and exits with code 1; a file that matches no format is reported as unrecognised and still exits with code 0.

## Texture viewer

Double-click a `.ttpf` texture store, or a type-5 RAGE resource row, to open it as a texture. Right-click either and choose **Open as Texture** to open it from the menu.
A store with one texture opens the single-image viewer. A store with several opens the dictionary viewer: a scrollable list with thumbnails and metadata on the left, and the selected texture on the right.
Double-click an entry, or press Enter, to open that texture in its own window.
Both windows share fit-to-window scaling, wheel zoom, drag panning, a transparency checkerboard and a mip selector when more than one level is available.

Decoding lives in `lforge-texture`, outside the UI.
It decodes format 28 as linear RGBA8, formats 71 and 72 as BC1, format 77 as BC3, format 80 as BC4, format 83 as BC5 and formats 98 and 99 as BC7, with row-major 4 x 4 blocks.
Format 54 is decoded as R16_FLOAT as a candidate reading; no simple-2D sample confirms it.
Only simple 2D textures are decoded. A kind that is not 2, or an array of more than one slice, is reported as unsupported.
Block storage classes `0x20` (zlib) and `0x00` (stored) are decoded. Other storage classes are reported by value and not decoded; the UI and map stores sampled in this build commonly use class `0x04`, whose content is unknown.
RDS5 levels are stored smallest first and the stream is right-aligned in the descriptor range, so the viewer reads level 0 from the end of that range. The descriptor's mip word is shown, but its relation to a level count is not established.
A type-5 RAGE resource row whose system segment passes the dictionary grammar opens in the same dictionary viewer. The viewer reads the system and graphics split from the row's chunk table and page map. A type-5 row that is not a dictionary, or whose split cannot be established, opens in the Binary Inspector instead.
Native dictionary records carry one stored level in the sampled assets. A non-zero `+0x40` stores that level as a 4 KiB tile grid; the viewer reorders it before decoding. Only level 0 is exposed; the raw mip word is shown without turning allocation padding into another level.

## RPF9 archives

The explorer opens RPF9 and ZIP archives like folders. Double-click one to browse it.
Archives are recognised by their contents, so the file extension does not matter.
Archives stored in other archives open the same way, up to 8 levels deep.
The explorer decompresses each one to a temporary file, up to 512 MB each and 2 GB per chain.
To see the raw archive bytes, right-click it and choose **Open in Binary Inspector**.

When the RPF9 table of contents is stored without encryption, Leonida Forge reads its native entries directly.
In retail game archives the engine processes the table before reading it.
For those archives Leonida Forge can authenticate the table against a compatible local game executable that you select, and then list the archive's own entries.
Without such an executable, or when authentication fails, it offers to recover entries by scanning the data instead.
That is scan recovery, not a complete native archive index, and it does not make this a full native GTA VI RPF9 reader.
The first visit reads the whole archive. A 773 MB archive takes about 2 seconds from the disk cache.
The index goes to `%APPDATA%\Leonida Forge\cache\rpf` and is reused until the archive's size or modification time changes.
Recovered entries and native entries are never mixed in one list.

## Local executable

Authenticated native listing needs a game executable that matches the archive, for example the game's main `.exe` from your own installation.
Choose **File > Select Game Executable…** and pick the file. **File > Clear Executable** removes the selection.
Only the path is stored, in the settings file above.
Leonida Forge opens the executable read-only, never copies or modifies it, and stores no keys, key state or IVs.
Nothing is downloaded, and no key service is used.
The recognizer checks the executable's structure and fails explicitly when it finds no compatible state, so a changed or unrelated executable simply does not authenticate.
If the file is moved, replaced or unreadable, Leonida Forge reports that and asks you to select it again.
Each time an archive is opened, the executable is checked against the file that was selected.

Inside an archive:

- `Recovered Entries` has one folder per detected kind, such as `XML`, `PSIN` or `Resources`.
  Files are named after their archive offset, for example `0x000000B000.xml`. Original names and folders are unknown.
- `Resource Pages` has one file per page of each reconstructed resource.
- `Unrecovered Regions` holds bytes that are not zlib streams, shown as stored.

An entry is complete when it starts with a known file signature and ends with a chunk shorter than 64 KiB.
Entries without a known signature are unverified and may be parts of larger files.

`--texture N` reconstructs the bytes of one RDS5 element through every block its descriptor names, in the order the descriptor declares, and reports the chain: descriptor fields, virtual range, selected block count, storage classes, stored length, padding, the reconstructed length and whether the chain is complete. The report lists the components separately: descriptor, block selection, storage class, decompression and virtual reconstruction have a supported byte-level path, while pixel format, element ordering and mip selection are not established. `--output FILE` writes those bytes; `--overwrite` replaces an existing file. The bytes are the element's stored representation, not a decoded image: no pixel format is established, so nothing is interpreted as texels. The unit-size fits in the research are candidate extent relationships, not byte scales, and the application uses none of them.

A RAGE resource is stored as one zlib stream per page, system pages first.
Leonida Forge reads the page counts from the resource's page map and takes the pages from the streams that follow.
A resource file holds its system pages, then its graphics pages.
A resource is complete when every declared page is there and the page sizes fit the pattern seen in GTA VI data.
It is partial when pages are missing, and unverified when its page map fails validation.
These rules come from observed data, not from game code.

```sh
lforge archive info data.rpf --json             # header fields and a recovery summary
lforge archive list data.rpf --json             # entries, resource pages and unrecovered regions
lforge archive resource data.rpf 0x2010 --json  # pages and checks of one resource
lforge archive resource data.rpf 0x2010 --drawable --json # its drawable structure
lforge archive resource data.rpf 0x2010 --dictionary --json # its texture dictionary
lforge archive resource data.rpf 0x2010 --dictionary --record 3 --json # one record
```

When the archive header declares a trailing region, every stored payload ends where that region begins, and the region's own contents are reported as undecoded. An archive whose header declares no trailing region keeps the whole file.

`--drawable` reconstructs a resource and walks the drawable structure in it: the header fields, the four LOD slots, each model's geometry array and bounds array, each vertex buffer's element, layout and declaration arithmetic, index descriptor counts and ranges, and the shader group with its parameter hashes and slot states. A resource counts as a drawable when its header and chain have that shape, not from a local type ID. Every pointer either resolves inside a reconstructed segment or is reported as an issue, an array is clamped to the entries that fit, and the report is partial until every record resolves. The model aggregate is checked against the union of its per-geometry bounds within `2e-3`; a one-geometry model carries only the aggregate and that check is reported as trivial. The header union is a separate check with its own measured delta; the research records no tolerance for it, so the model tolerance is shown as a display threshold and a difference there never invalidates the drawable. The graphics segment base is not stored; it is reported only when two distinct graphics pointers support one candidate, and otherwise as undecided. Materials stay hashes: parameter values are candidate preimages, texture keys are not resolved to dictionary records, and the resolution state is reported as not evaluated. Vertex positions, triangles, meshes and texture-store joins are not reconstructed.

`--dictionary` reads the reconstructed system segment as a texture dictionary: the root pointers and counts, the sorted hash array, the value array, and one entry per `0x70`-byte record with its allocation extent, width, height, format id, mip word and name-record state. Recognition fails closed and names the step that failed. A name hash is only checked for the variant that carries one, and only when its text is reachable and terminated inside the 64-byte window. A hash that several records share leaves every one of them a candidate; none is selected. `--record N` shows one record in full. The graphics segment is not parsed and no pixel is decoded.

`--no-cache` neither reads nor writes the index cache.

`lforge archive recover` exports one recovered entry at a time, for archives whose native table of contents cannot be decrypted.

```sh
lforge archive recover data.rpf --list --json             # the recovery candidates
lforge archive recover data.rpf --id 0x0000000080 --output file.bin
```

A candidate is one recovered entry, identified by the archive offset of its first stream. The scan produces the same offset again for unchanged data, so the id is stable across scans. `--list` reports each candidate's observed properties, the offset, byte range, zlib compression, compressed and decoded sizes, and whether the bytes start with a known file signature, apart from its inferred ones, the content kind and the completeness status. Candidates are not native entries. They have no original names or paths, and the list is not a complete archive inventory.

`recover --id ID --output FILE` re-decodes one candidate and writes its bytes with the same output safety as `archive extract`. The streams are checked against the index as they are read, the output goes through a temporary file and replaces an existing file only with `--overwrite`, and a failed decode leaves no partial file. A partial or unverified candidate is written with a note that bytes may be missing. A decode that succeeds is not proof that the bytes are an authentic original file.

`archive info`, `archive list` and `archive recover --list` carry explicit schemas (`leonida-forge.archive-info/1`, `leonida-forge.archive-list/1`, `leonida-forge.recovery-list/1`). A payload that starts with `PSIN` is reported with the kind `psin`; earlier builds called it `pso`. Nothing establishes a relation to a PSO format. A recovered PSIN entry gets the neutral display name `.bin`, which the listing marks with `extension_synthetic`; no PSIN extension is established and none is published.

Where the table of contents is stored without encryption, it can be read directly instead of scanned. With a compatible local game executable, `--executable` authenticates a processed table of contents first.

```sh
lforge archive metadata data.rpf --entries --executable game.exe   # the native entries and how each one reads
lforge archive ls data.rpf --executable game.exe --limit 20 --json  # one record per authenticated row
lforge archive search data.rpf --executable game.exe --name timecycle --json
lforge archive search "GAME_DIRECTORY" --executable game.exe --type 0 --readable true --json
lforge archive manifest data.rpf --executable game.exe --format jsonl --output manifest.jsonl
lforge archive extract data.rpf --row 42 --output file.bin --executable game.exe
```

`archive ls`, `search` and `manifest` reuse the same native table-of-contents reader as `archive metadata`; they never list unauthenticated rows, extract payloads or write key state. `ls` pages with `--offset` and `--limit`. `search` filters by resolved name substring, stored `hash64`/`key32`, type ID, confirmed extension, readability, payload-transform state and archive path; it accepts one archive or a directory of archives. `--hash` matches only the column that the row's established type class makes authoritative: a 64-bit search never matches a 32-bit-class row, a 32-bit search never matches a 64-bit-class row, and an unknown class matches neither. A row behind the payload transform reports its cipher descriptor as `payload_cipher`: cipher type, algorithm, key identifier and 16-byte parameter. Its `contents.state` names `transform_available` when the executable key state exists and `transform_key_missing` when it does not. An available transform reports `contents.readable` as `null` until a decode is attempted, so `--readable false` does not select it; a missing key reports `false`. `manifest` writes one record per row with an explicit schema (`leonida-forge.native-manifest/1`), as one JSON document or as JSONL with a header record followed by one row per line. 64-bit hashes, keys and payload offsets are strings so no value loses precision. `.names.txt` and `--name-file` work as they do for `archive metadata`.

Entries are identified by their row number in the table. `archive metadata --entries` lists them and reports, for each one, whether its contents are readable as stored, readable after supported decoding, or unavailable. When an entry is unavailable it gives the reason: an unsupported payload transform, an unsupported compression mode, a companion file that is missing or invalid, or malformed metadata. A transformed entry also reports the cipher descriptor the engine would use; it is decoded when the executable that authenticated the metadata provides the algorithm-`0x11` key state. Readability is decided from the table of contents and the entry structure. A chunked row whose table and sizes fit is `validated`, not `decoded`: a corrupt zlib stream still fails when it is read, and `archive extract` then writes nothing and reports the error. It also reports whether the table was authenticated by a signature check or read without one because the archive needs no processing pass.

`archive extract` writes one entry to `--output`, decoded where its storage is supported. It handles stored bytes, raw DEFLATE, chunked payloads whose chunks are zlib streams or copied, including entries whose bytes live in a companion file next to the archive, and payload-transformed entries when the executable that authenticated the metadata provides the algorithm-`0x11` key state. Decoding is incremental: stored bytes are read in bounded buffers, transformed on read, inflated per chunk, and written through a temporary file in the destination directory. Large zlib chunks are spooled to an anonymous temporary file instead of memory. `--max-output-bytes` bounds one extraction (default 512 MiB). It refuses encrypted or processed metadata, transforms or compression modes it cannot decode, and companions that are not available, rather than writing wrong bytes. The output replaces an existing file only with `--overwrite`; a failed decode leaves no partial file behind.

`archive inspect` reads one row or ZIP entry through the same decoder and reports its structure without writing a file:

```sh
lforge archive inspect data.rpf --row 42 --json --executable game.exe
lforge archive inspect data.rpf --row 42 --blocks --verify
lforge archive inspect outer.rpf --executable game.exe --enter row:12 --row 4 --json
lforge archive inspect outer.rpf --executable game.exe --enter row:12 --enter zip:3 --row 7 --json
lforge archive inspect outer.rpf --enter row:12 --zip 0 --json
lforge archive inspect outer.rpf --row 42 --raw --json
```

`--enter SEL` is repeatable and descends into an archive stored in the current one. `row:N` selects a native RPF9 row; `zip:N` selects a ZIP entry by central-directory index. The entered payload must be a valid archive recognised from its contents, never from its name. `--row N` and `--zip N` select the final entry in the last archive; without either, `archive inspect FILE` keeps reading row 0, and with `--enter` it inspects the entered archive itself. Entries are identified by index at every level, so two entries with the same visible name are never confused. The ZIP reader keeps one entry per central-directory record: records that share a full name stay distinct entries with their original indices, and `zip:N` always names the record at position N. The same `--enter` selectors work with `archive extract` and `archive ls`.

An RDS5 row is reported field by field: header values, the record array, the ETPF chunk position and extent, the entry table, and one catalogue entry per data block with its stored range and storage class. Class `0x20` is a zlib stream and class `0x00` is stored bytes; the six other classes observed in data are reported by value and never decoded, and a block of the zlib class without a zlib header is reported as unidentified instead of being decoded by guesswork. `--verify` inflates each zlib block, reports the blocks that fail and compares the decoded total with the declared uncompressed total. Each element's descriptor fields are reported as the values they store, and the texture key table is reported as a count and an increasing order, never as key values. An RBF0 row is reported as its parsed token stream: the header variant and number width, the body offset and length, the name, object, field, attribute and text-node counts, the deepest nesting, one record per name definition with its length and digest, and the string and length-prefixed values as totals, lengths and digests. A GFx row is reported as its version-42 header, declared length, RECT extent, 8.8 frame rate, frame count and tag walk with each tag's code, length and depth. A PSIN row is reported with its section walk, family, descriptor or block table, section table, body structure and checksum result; its `LSCH` and `PMAP` families are separate code paths. An EDUP row is reported with its entry count, distinct field counts, entry framing and opaque trailing blob. An ADAT row is reported with its header, per-stream tables, chunk records, block classes, packet and padding totals, framing violations, rate values and position table; packets are counted, never materialised. A KB2 row is reported with its variant, header fields, frame index checks and audio record counts. Rows in the RPF9 format are reported by signature only. The row is read through the streaming decoder; nothing is extracted and nothing is written.

Structured inspection reads the decoded logical payload: an entry stored as raw DEFLATE or in chunks is decoded first, and a transformed entry is decoded with the executable key state. A transform that cannot be verified is reported as a decoding failure instead of being passed to a parser. `--raw` asks for the bytes as they are stored instead. For a row stored compressed, in chunks or behind a transform, that is the stored representation before decoding, which may include alignment padding; it is never presented as the row's decoded contents.

The inspection document uses schema `leonida-forge.format-inspection/2`. Version 2 adds `provenance`, `representation` and `failure_stage`; the version 1 fields keep their meaning. `provenance` reports the root file, every `--enter` step in order with its selector and archive format, the per-level authentication status where an RPF9 table was opened, the decoded byte total, and that a valid metadata signature does not authenticate payload bytes. `representation` states whether the inspected bytes are logical or stored and whether they were decoded, with the decode error when they were not. Offsets stay hexadecimal strings.

Nested traversal enforces the same limits at every level: at most 8 archives in a chain, 512 MiB decoded per intermediate archive, 2 GiB decoded per chain, 1M rows or ZIP entries, checked offset arithmetic, cancellation and automatic temporary-file removal. An RPF9 archive at any depth is opened through the same metadata authentication as a top-level one; without a compatible executable, a processed table of contents is refused rather than read unverified.

`archive inventory` walks supported archives and writes a deterministic, streaming manifest of their entries:

```sh
lforge archive inventory data.rpf --executable game.exe --recursive --output inventory.jsonl
lforge archive inventory "GAME_DIRECTORY" --executable game.exe --recursive --format json --output inventory.json
lforge archive inventory data.rpf --recursive --content-format psin --json
```

The root is one archive or a directory searched for `.rpf` and `.zip` files. `--recursive` enters an entry only when its decoded payload is a valid archive of a supported format; a file name never decides that. Each entry record carries its root name, the selector chain to the containing archive, the final `row:N` or `zip:N` selector, the stored and logical sizes, the encoding, payload readability, the containing archive's metadata authentication, the recognised content format and the earliest failure stage. `reproduce` gives the equivalent `archive inspect` command, with `ROOT` standing in for the root path.

JSONL writes a header record, then archive, entry and error records, then a summary. `--format json` writes one document with the same header, a `records` array and the summary. Records stream: the walk never holds the inventory in memory. The summary `status` is `complete`, `complete_with_skips`, `truncated`, `cancelled` or `failed`. A truncated or failed run exits non-zero and its manifest never claims to be complete.

Limits apply to the whole traversal: archives in a chain (`--max-depth`), archives opened (`--max-archives`), entries recorded (`--max-entries`), largest decoded payload (`--max-entry-bytes`), total decoded bytes (`--max-decoded-bytes`) and temporary storage held on one chain (`--max-temp-bytes`). Recognition reads a bounded prefix first; a ZIP entry is decoded in full only when that prefix matches a known signature or the format needs structural validation. A payload that cannot be decoded keeps the stage that stopped it (`compression`, `transform`, `source`, `authentication`, `limit`, `decoding`) and is never reported as an unknown format. The inventory payload record keeps a boolean `readable`; a transform-available row is reported as `false` with status `transform_available` and is not decoded. `--content-format`, `--type`, `--name`, `--hash`, `--readable`, `--failure-stage` and `--depth` select which entry records are written; the summary still counts every discovered entry.

The schema is `leonida-forge.archive-inventory/1`. Root names are relative to the caller's root, and no absolute directory is written. 64-bit hashes and keys are hexadecimal strings.

The `validated` state in `archive metadata`, `ls`, `search` and `manifest` is a structural state: it is decided from the table of contents and the chunk table, without inflating a stream. Use `archive inspect --verify` to check a row's streams, `archive verify` to decode and hash every row of one chunk encoding, or `archive extract` to obtain the bytes.

RPF9 stores a hash of each entry's path, not the path. `archive metadata --entries` always shows the stored hash and key. A name table can add candidate names, but a name is display data: it never changes a row's key, a payload offset, an authentication result or an extraction destination. Two LUT files, `rpf9-hash64.lut` and `rpf9-key32.lut`, are embedded in the binaries and always applied; a file with either name beside the executable is read as well and merged over it, which refreshes the table without a rebuild. `--name-file FILE` is repeatable and accepts a `.names.txt` table or a Leonida Forge LUT; without it, `<archive>.names.txt` next to the archive is used when present. The `.names.txt` format is UTF-8, one entry per line: a candidate path, or `hash64:HASH<TAB>NAME` and `key32:HASH<TAB>NAME` for a declared key. Candidate paths are verified by hashing them with the type's class. A declared name is verified only when its normalized form or its stem reproduces the key; otherwise it is reported as unconfirmed. Use `--archive-path`, `--mount-prefix` and `--extension` to describe paths that the built-in `rpf` mapping cannot.

The desktop explorer labels an entry with a verified unambiguous name, otherwise with the stored key in canonical hexadecimal form. `rpf` to type 0 is the only confirmed extension, so other type IDs get no invented extension. Types 11, 14 and 255 use the 32-bit key class, established from the executable's per-type tables. For type 255 the published key32 records resolve 125 rows; for type 11 the key32 records resolve 134 of 865 rows, whose stored keys reproduce `joaat` of harvested path stems. Types 11 and 14 still have no confirmed extension, and a type 11 name is a hash preimage, not an established original filename. Row numbers remain the entry paths and stay in details. Names come from the same embedded LUTs, `<archive>.names.txt` tables, and candidates in the LUT files beside `leonida-forge.exe`; a `.lut` next to an archive is not read.

The type-255 row count appears in several measurements that are not interchangeable:

- A **harvest match record** is one candidate string in one payload whose hash equals a stored key. One payload can produce many records.
- A match record carries `verified_as` when the candidate is a verified RBF0 field, naming it `field_name`, `string_value` or `attribute_value`. Without it the string was extracted from payload bytes without a parsed format establishing it. Either way a match is a hash preimage, not an established original filename.
- **Distinct matching keys** are the unique hash values among those records.
- **Rows matched by harvesting** are table rows whose class-authoritative key is one of those hashes. One key can address several rows, so the row count can exceed the key count.
- **Rows resolved by the final LUT** are rows whose class-authoritative key is in the published, validated table, after duplicate, ambiguous and provenance-rejected candidates are removed.
- **Rows rejected through type-class validation** matched only through a column their type class does not make authoritative, or through an unknown class.

The harvest matched 177 type-255 rows, the published key32 table holds 106 type-255 keys, and the final table resolves 125 type-255 rows. The key and row counts differ because rows can share a key; the harvest and final row counts differ because validation and publication are stricter than a bare match. The counts come from different stages and are not adjusted to agree.

A native archive can be shown by the folders its verified relative paths describe, or as one flat list of every row. The toolbar switches between them, the choice is stored in settings, and switching re-lists from the table of contents already in memory. Row paths stay `<folder>/Row NNNNN` in both modes, so selection, preview, inspection and export keep working. The filter box matches a visible label, a stored name hash or key, a type, or a resolved candidate, without indexing the archive.

When a verified name is a relative path, the explorer shows it as folders, so `levels/americas/props/vampires_metadata.rpf` is filed under `levels`, `americas` and `props`. The archive stores no folders; each entry keeps its path `<folder>/Row NNNNN`, so a row has exactly one path. Names are untrusted input: absolute paths, `.`, `..`, empty components, drive letters and characters Windows refuses are never used to build a folder, and such a row keeps its stored key as the label. Rows without a usable path are listed after everything else in `Unnamed Entries`, labelled by their stored key. An archive where no name gives a usable path is listed flat at its root. The only folders an RPF9 archive stores itself are nested archives, which stay entries.

The native index and candidate pipeline are available without a network service:

```sh
lforge names index "GAME_DIRECTORY" --executable game.exe --json
lforge names harvest "GAME_DIRECTORY" --executable game.exe --sources payloads,executable --output results.jsonl --json
lforge names export results.jsonl --format lut --output resolved.lut --json
lforge names audit --research path/to/research/names --json
```

`names index` authenticates each `.rpf` recursively and builds an in-memory index of stored keys and rows. It reports per-type counts of which key column each row populates, separately from the class the executable establishes. `names harvest` extracts bounded path-like strings from readable payloads and initialized executable sections, hashes a small set of variants, and writes local JSONL evidence for hash matches; its summary breaks matches down by source, namespace, archive and type, and reports unresolved and ambiguous keys. `names export` writes one validated LUT per namespace (`resolved.hash64.lut`, `resolved.key32.lut` when both are present) and reports which source and namespace each accepted record came from. `names audit` re-hashes every bundled LUT record, reports unverified entries, ambiguous keys, duplicate spellings and unsafe paths, and compares the bundled tables with a Research checkout's `names` directory when `--research` is given. It reads only and downloads nothing. A hash match is a candidate, not proof of the original developer filename; 32-bit matches are weaker. The LUTs embedded in the binaries are the verified mappings published in the research repository; copy a newer file beside the executable to refresh them.

## RPF9 archive census

`archive census` counts what every reachable entry is, instead of listing it:

```sh
lforge archive census data.rpf --executable game.exe --recursive
lforge archive census "GAME_DIRECTORY" --executable game.exe --recursive --output census.jsonl
lforge archive census data.rpf --executable game.exe --recursive --entries --json
```

Each entry is classified from its metadata and at most 64 decoded bytes, plus a full parse of a document up to 4 MiB when the head looks like XML. The classification keeps three properties apart: the entry's numeric type, the payload's format, and what the application can do with the bytes. A type never decides a format, and an extension is applied only when the classification establishes it: the archive's own name, `rpf` for an RPF9 payload, `xml` for a validated document. Everything else is unresolved with a reason.

The document uses schema `leonida-forge.rpf9-census/1`. JSONL writes a header record, one record per combination of type, identification, storage, transform, payload state, confidence, extension and capability, then a summary; `--entries` adds one record per entry. Each combination carries the number of entries, the archives it was seen in and samples with the archive, the selector chain to the row and the first 32 bytes of the decoded head. The summary reports the archives opened, the entries classified, the per-type totals, the combinations and any archive that could not be read.

`--recursive` enters an entry only when its decoded payload is an RPF9 archive. When every chunk of that entry copies its bytes, the nested archive is read at its payload offset; otherwise its payload is decoded into temporary storage first, bounded by `--max-nested-bytes` and `--max-spool-bytes`. `--max-depth`, `--max-archives` and `--max-entries` bound the run, and a run that hits one reports `stopped` rather than claiming to be complete. Classification reads a decoded chunk per entry, so a complete census of a large installation is not cheap; `--max-entries` is the honest way to bound it.

## RPF9 chunk-encoding verification

`archive verify` decodes every row of one chunk encoding to its end and hashes the result:

```sh
lforge archive verify levels.rpf --executable game.exe --encoding 4 --recursive --output encoding-4.jsonl
lforge archive verify levels.rpf --executable game.exe --enter row:1029 --encoding 4 --output nested.jsonl
```

Each record names the archive chain, row, type, extension, stored and logical sizes, layout, read source, chunk count, chunk methods and the stored prefix. The verification block reports whether the chunk table parsed, whether every chunk decoded, whether the logical size matched, the SHA-256 of the complete decoded payload, the payload classification and, on failure, a category and the decoder's message. Its `integrity` field names what was checked: `zlib-adler32` for zlib-only chunks, `zlib-adler32-and-copy` when both kinds occur, `sizes-and-copy` for copy-only chunks, or `sizes` for no chunks. The command streams, so memory stays bounded and no payload is retained. It exits non-zero when any candidate fails, and the summary counts the outcomes by type, error, prefix length and method set.

`--enter row:N` verifies one archive stored inside another without extracting it to a file. `--max-depth`, `--max-archives` and `--max-entries` bound the traversal; `--max-nested-bytes` and `--max-spool-bytes` bound temporary storage. A row behind the payload transform is verified with the executable's algorithm-`0x11` key state, as extraction does.

## Catalog extraction and package validation

`catalog extract` reads the XML metadata documents in authenticated RPF9 rows and writes one bounded observation per source item. `catalog validate` checks a website publication package without extracting it.

```sh
lforge catalog extract common.rpf --executable game.exe --source-id common \
  --output observations.ndjson --report extraction.json
lforge catalog validate catalog-export.zip --json
```

The extraction writes NDJSON to standard output unless `--output` is given. Diagnostics and summary lines go to standard error, so a consumer can parse standard output without filtering it. The observation schema is `leonida-forge.catalog-extraction/1`; the report schema is `leonida-forge.catalog-extraction-report/1`. Each observation carries the source row hash, payload SHA-256, XML root and element path. A number keeps its stored value; `unit` is null unless the element name states a unit. A missing field is absent, never defaulted. Nested RPF archives (type 0) are excluded before decoding and counted as `excluded`. A non-XML row above the materialization limit is classified from a 64 KiB prefix and counted as `notXml` and `prefixOnly`; only an XML document above the limit is `tooLarge`. Rows the decoder cannot read are counted by cause (`unsupportedTransform`, `unsupportedCompression`, `missingSource`, `malformedMetadata`, `decodeFailed`), with `unsupported` as the total for payload failures, and make the status `partial`. `--max-row-bytes` bounds the XML document materialized in memory (default 64 MiB); it is not an extraction limit.

The validation result uses schema `leonida-forge.package-validation/1`. Exit code 0 means valid, 1 means the package is invalid or the command failed, and 2 means invalid usage. Validation covers ZIP paths, entry count, sizes, compression ratio, declared SHA-256 digests, duplicate JSON keys, manifest fields, the five catalog schemas, record identity uniqueness and relationship endpoints. A version 1.0.0 package without catalog data remains valid, as does a version 1.2.0 package whose images name their record and carry a primary image and a thumbnail. The command never writes to the package and never extracts an entry to a directory.

## Vehicle bodies and preview images

`vehicle bodies` finds the drivable vehicle models and `vehicle previews` renders them. Neither command writes to the game installation.

```sh
lforge vehicle bodies --archive "D:/GTA VI/levels.rpf" --executable "D:/GTA VI/game_scarlett_master.exe" \
  --names model-names.txt --output bodies.json
lforge vehicle previews --bodies bodies.json --archive "D:/GTA VI/levels.rpf" \
  --executable "D:/GTA VI/game_scarlett_master.exe" --textures "D:/GTA VI/data/ttdb" \
  --colors vehicle-colors.json --output previews/
```

A vehicle body is a type 3 fragment named `<model>_hi.#ft` inside an archive that an unresolved top-level row of `levels.rpf` stores. `vehicle bodies` enters those rows, decodes the large type 3 candidates, reads the names in their headers and keeps the most detailed body per model. The document records the row numbers and the header, never an absolute path, so it can be regenerated on another machine. Names come from a text list or from a JSON array with `Name`, `modelName`, `model` or `name`.

`vehicle previews` renders a 1024x1024 primary WebP and a 320x320 thumbnail per body, with transparency, and writes `previews.json` with schema `leonida-forge.vehicle-previews/1`. The manifest names the model, so the exporter resolves the record with the same function that builds the identifier. A model that decodes no mesh, or whose resource has no inferable system/graphics boundary, is reported and skipped; it never stops the run.

Rendering is cached by identity. The identity covers the body digest, the material-policy revision, the shader revision, the digest of every texture store root, the paint colour, the camera framing, both output sizes and the encoder profile. A cached pair is reused only when the entry matches and both files decode at the expected size. Outputs are written through a temporary file and renamed, and the cache entry is written after both images.

## Development workflow

Development is feature-driven, not research-iteration-driven.

1. You define or approve a concrete feature.
2. Inspect the application and the canonical research before writing code.
3. Use established format knowledge when it exists; implement the feature directly.
4. When a research dependency blocks the feature, name the exact missing knowledge and propose a focused research request.
5. Research runs only for an approved dependency, and its result is reviewed independently before integration.
6. Resume the feature with the supported capability, and keep its description accurate.

Research findings are knowledge, not a task list. An open question is not a schedule item. The application describes what it actually does, and a capability that is structural, experimental or partial is labelled that way.

## AI Contributions

**AI-enabled, not AI-driven.**

We welcome the use of AI as a development tool, but contributors are expected to understand, review, and take responsibility for their work.

AI-generated code is not inherently a problem. Unreviewed, untested, or poorly understood code is.

- Understand the code you submit and be able to explain your changes.
- Review and test AI-assisted contributions before submitting them.
- Follow existing conventions instead of introducing unnecessary abstractions, boilerplate, or documentation.
- Keep pull requests focused, maintainable, and backed by actual effort.

Low-effort, AI-generated pull requests submitted without meaningful human review or validation will be rejected.

**AI can assist your work. It should not replace your judgment.**

## Community

Questions, help and development discussion happen in the [Leonida Forge Discord](https://discord.gg/PJgVZCuWGf).

## License

Leonida Forge is licensed under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE.md](LICENSE.md).

## Disclaimer

Leonida Forge is an independent, unofficial community project and is not affiliated with or endorsed by Rockstar Games or Take-Two Interactive.

Grand Theft Auto and related trademarks belong to their respective owners.
