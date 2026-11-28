# 0DRP metadata resources

`0DRP` is the third form a type 11 or type 111 metadata row can hold: the same
self-describing tables a `PSIN` container stores, placed inside a RAGE resource
instead of a container. This document describes how Leonida Forge decodes it,
where the code lives and what the decoder was validated against. The format
itself is specified in the research repository (`formats/metadata`); this
document is about the implementation.

`0DRP` is a signature, not an established format name. Nothing here claims the
bytes mean `0DRP`.

## Where the code lives

| Layer | Path | Responsibility |
| ----- | ---- | -------------- |
| Decoder | `crates/rage9/src/odrp/mod.rs` | Header, tables, blocks, records, values, roots, limits, errors, `decode` |
| Decoder tests | `crates/rage9/src/odrp/tests.rs` | Synthetic resources over every block kind and every failure |
| Shared value model | `crates/rage9/src/psin/pso.rs` | `Value::Text`, `ArrayElements`, `Content::Elements` added beside the PSIN variants |
| JSON and XML views | `crates/core/src/odrp.rs` | `document_json`, `document_xml`, `counts`, `counts_json` |
| Shared metadata API | `crates/core/src/metadata.rs` | `Document::Odrp`, chosen by signature |
| CLI | `apps/cli/src/inspect.rs` | `--metadata-output`, `--metadata-xml` |
| Desktop | `apps/desktop/src/viewers/metadata` | The existing Metadata Viewer |
| Validation harness | `crates/rage9/examples/odrp_population.rs` | Decodes every reachable payload and tallies outcomes |

The decoder exists once. The CLI, the desktop and any later consumer drive
`lforge_core::metadata`; none of them parses a resource form itself.

## The stored layout

Read from GTA VI resources and checked against them. Offsets are in the system
segment.

| Offset | Field | Reading |
| ------ | ----- | ------- |
| `+0x00` | zero | A zero `u64` |
| `+0x08` | page map | A system pointer to the page map |
| `+0x10` | tag | `0DRP` |
| `+0x14` | object type | `0x7A` in all 15,768 observed resources; meaning not established |
| `+0x18` | zero | A zero `u64` |
| `+0x20` | root block | The block the header names as the root, counted from one; equals the derived root in all 15,768 resources |
| `+0x28` | structure table | System pointer |
| `+0x30` | enumeration table | System pointer, zero when there are none |
| `+0x38` | block table | System pointer |
| `+0x40` | pointer | A system pointer the population does not explain |
| `+0x48` | `u16 × 4` | Structure, enumeration and block counts, then a word of unknown meaning |

A structure record is 32 bytes: `{u32 name, u32 signature, u32 flags, u32 zero,
u64 member pointer, u32 size, u16 zero, u16 field count}`. Where the `PSIN` form
stores eight `0xAA` bytes the resource form stores the pointer to that
structure's field records.

A field record is the 16 bytes `PSIN` uses: `{u32 name, u32 offset, u32 type
word, u32 auxiliary}`. The type word is a low-16 code and a high-16 qualifier,
the same split `PSIN` stores.

An enumeration record is 24 bytes: `{u32 name, u32 signature, u64 value pointer,
u32 count, u32 zero}`, followed by `count` value records of `{u64 value, u32
name, u32 zero}`.

A block record is 16 bytes: `{u32 type word, u32 byte length, u64 pointer}`. The
pointer names the segment and the offset of the block's bytes, so one block may
lie in the system segment and another in the graphics segment.

A reference is a `u64` of `(byte offset << 20) | block`, the block counted from
one, zero for null. A reference names a block and an offset in that block; it
never names a segment directly, which is why one word addresses either segment.

### Values

The container layouts are the ones `PSIN` stores, with two exceptions:

- `0x5c` arrays and `0x75` maps store `{u32 length, u32 capacity, u64
  reference}`; a `0x52` array stores `{u64 reference, u16 length, u16 capacity,
  u32 zero}`.
- A `0x42` field is an eight-byte reference into a type `0x10` block, whose
  elements are NUL-terminated UTF-8 strings. A `0x65` bit set is eight bytes.
- A map's two words are the number of bucket records and the number of entries
  those buckets hold.

`0x44` text slots were observed but their layout is not established. Their
bytes are kept and reported; no attempt to read a string from them is made.

### Blocks

A block's type word says what the block holds:

- The name of one structure: the block is `length / size` whole records of that
  structure. This is the common case: the two most frequent block type words in
  the population, `0x99331089` and `0xA8478889`, are both structure names.
- A pool code `PSIN` also uses (`0x10` text, `0x4a` hash32, `0x14` word32,
  `0x16` word64, `0x33` word128, `7` reference64): a pool of that element.
- A field code whose element width the type table establishes: a pool of
  scalars of that type.
- Anything else: kept as bytes, counted as unsupported.

## The document model

`odrp::decode(system, graphics, &Limits)` takes the two reconstructed segments.
It returns an `odrp::Document`:

- `header` — the words above, with `extra_pointer` and `unknown_word` reported
  as stored.
- `structures`, `enums` — the schema, as the resource defines it.
- `blocks` — each block with its index, stored type word, segment, offset,
  length and `content`: `Records` of one structure, a `Pool` of a known element,
  `Elements` of a field code's scalars, or `Unsupported` with the reason.
- `roots` — the structure blocks no decoded reference reaches, in block order.
  The derivation does not consult the header's root block, so the two readings
  can be compared; a header root the derivation does not hold is reported as an
  issue.
- `issues`, `unsupported_blocks`, `unresolved_references`, `truncated` — what
  does not add up.

A stored hash is never replaced by a name. A name table passed to the views is
applied beside the hash, as it is for a `PSIN` document.

## Decoding status

| Status | Meaning |
| ------ | ------- |
| `decoded` | Every declared block was read to its full extent, every reference bound, nothing was truncated |
| `partial` | A block could not be divided into records, a reference bound nowhere, or a limit cut the document short |
| `failed` | The header or a table is inconsistent with the resource; the reason is reported |

A field whose type code is not decoded keeps the bytes its extent covers and
does **not** by itself make a document partial, because its storage is
accounted for. A block that cannot be divided into records, or a reference that
binds nowhere, does.

The population reaches `partial` once, for `data.rpf` row 476: four of its 186
blocks are typed `0x31`, `0x4d`, `0x4f` and `0x5c` and none of those blocks has a
structure, a pool element or an established width.

## Limits

`Limits` is shared with the `PSIN` decoder: `max_depth`, `max_records`,
`max_elements`, `max_text` and a node budget. The header counts are bounded by
`MAX_STRUCTURES`, `MAX_ENUMS` and `MAX_BLOCKS`, each 16,384.

Every read is bounds-checked against the block's extent and every block against
its segment, so a hostile resource cannot read outside the payload. A block or
record count above a limit sets `truncated` and reports how many were read; it
never allocates past the limit.

## Shared metadata API

`lforge_core::metadata::decode` returns `Document::Odrp` when the payload
carries the tag and the header shape. A resource needs its page table, so a
caller that has one calls `decode_with_split(payload, Some(split))`;
`decode_with_split(payload, None)` reports `Error::OdrpNeedsPages` rather than
guessing a split. The CLI builds the split from the row's chunk table with
`rpf::resource::page_split`; the desktop does the same through
`files::resource_split_with`.

A `0DRP` document adds to the API surface:

- `format()` — `0drp`.
- `schema()` — `leonida-forge.odrp-document/1`.
- `summary()` — structures, blocks, records, texts and depth.
- `status()`, `counts_json()`, `document_json(names, sample)`,
  `document_xml(source)`.

The JSON keeps a block's type word as a hash with `typeCandidates` beside it,
states each block's segment and offset, and lists the roots with the records
each holds. The XML carries the same values with `source` provenance.

## CLI

`0DRP` uses the metadata workflow `PSIN` already had; there are no
resource-form commands.

```text
lforge archive inspect <archive> --row R --metadata-output doc.json
lforge archive inspect <archive> --enter row:N --row R --metadata-output doc.xml --metadata-xml
```

`lforge archive inspect` without `--metadata-output` reports the table counts
and the decoder's notes.

## Desktop

The explorer's metadata gate accepts a classification whose `format_id` is
`psin`, `rbf0` or `meta-resource`, and the metadata arm stays ahead of the text
arm. The viewer splits the payload with the row's page table, decodes it and
builds rows:

- `header` — the tag's object type, the page counts, the word at `+0x20`, the
  unknown words and the extra pointer;
- `schema` — every structure with its signature, flags, size and fields, then
  the enumerations;
- `blocks` — every block with its segment, offset, length and what it holds,
  expanding into records, pool entries or elements;
- `roots` — the derived root blocks with their record counts;
- `issues` — whatever the decoder reported.

The status line reads `{status} · {rows} rows · {names} hashes named ·
{texts} text values`, so a resource that reports text values says so.

## Validation

`crates/rage9/examples/odrp_population.rs` walks archives the way the CLI does,
splits each payload from the row's page table and the page map, decodes it and
tallies the outcomes. It writes no document out and prints no name.

```text
cargo build --release -p lforge-rage9 --example odrp_population
target/release/examples/odrp_population "<GAME_ROOT>/data.rpf" \
    --executable "<GAME_ROOT>/<game executable>" --recursive --types
```

`data.rpf`, exhaustive:

| Measure | Result |
| ------- | ------ |
| Root archives walked | 1 |
| Nested archives entered | 41 |
| Entries walked | 23,075 |
| Resources carrying the tag | 15,768 |
| Payloads opened, split and decoded | 15,768 |
| `decoded` | 15,767 |
| `partial` | 1 (`data.rpf` row 476, four undecoded blocks) |
| `failed` | 0 |
| Limit refusals | 0 |
| Unresolved references | 0 |
| Resources with a note | 0 |
| Distinct payloads by SHA-256 | 15,672 |
| Row types | 1,286 type 11, 14,482 type 111 |
| Bytes | 848 to 14,876,672 |
| Structures per resource | 2 to 182 |
| Blocks per resource | 2 to 186 |
| Records per resource | 3 to 192,488 |
| Deepest nesting | 3 |
| Text values | 4,215,226 |
| Page shapes (system, graphics) | (1, 0) 15,609, (2, 0) 159 |
| Resources carrying enumerations | 1,310, 2,780 values in total |
| Object type bytes | `0x7A`, 15,768 |
| Root block words | 1: 1,247, 2: 14,485, 3: 35, 89: 1 |
| Resources whose derived root is the header's root block | 15,768 of 15,768 |

No observed resource had a graphics page, so no block was read from a graphics
segment; the graphics path is covered by synthetic tests alone.

### The 1,286 and the 15,768

The earlier census counted 1,286 resources of the `0DRP` form among 5,321 type
11 metadata rows. That walk classified rows from their head in the archives on
disk. This walk is recursive and counts every row that carries the tag, so it
adds the 14,482 type 111 rows stored inside the nested archives of `data.rpf`.
Both numbers are right about different populations: 1,286 is the type 11
subset, 15,768 is every row of either type the signature finds.

### What the population stores

- 85 distinct field type words were observed. They are dominated by `0x4a`
  (hash32, 29,327), `0x07` (reference, 28,966), `0x05` (embedded structure,
  17,224), `0x11` (14,722), `0x42` (text reference, 14,544), `0x75` (14,483) and
  `0x50` (14,482) with descriptor 2, then `0x21` (f32, 9,298), `0x14` (2,786) and
  `0x60` (enum, 451). 41 words occur once.
- 194 distinct block type words were observed, 182 of them once. They are
  dominated by `0x10` (text, 14,520), `0x101` (a bool block, 14,482) and
  structure names.
- Four blocks, all in one resource, have no structure, pool element or
  established width.

Automated tests cover the decoder, the views and both front ends: a valid
resource, embedded and inline arrays, scalar arrays, maps, a graphics-segment
block, a short or missing tag, a block outside its segment, unknown block and
field types, a self-embedding reference cycle, count and record limits,
enumerations and a block that is not a whole number of records.

Desktop validation is visual for the first frame and automated for the rest.
Two resources were opened on this machine and the window captured: `data.rpf`
row 476 (182 structures, 186 blocks, 20,000 rendered rows, status `partial`) and
`data.rpf!0x0C8F5AD65275E37D.rpf!0x0A3F3D02BA0CA848.zldbmt` (4 structures, 4
blocks, 19 records, 16 text values, status `decoded`, 355 rows). The second
painted its header, its schema, its blocks and its text values.

What remains unverified by hand: folding a row, typing in the filter and the
Copy Row button for a resource form. Their logic is shared with `PSIN` and
covered by tests.

## Remaining limits

- The meaning of the fourth `u16` at `+0x4E` and of the pointer at `+0x40` is
  not established. Both are reported, not interpreted.
- A `0x44` text slot's layout is unknown, so its 16 bytes are kept and not read
  as text.
- Four blocks in one resource cannot be divided; their bytes are kept.
- A structure or field name stays the 32-bit hash the schema stores. The
  viewer names 9,804 of row 476's hashes through the existing dictionary; the
  rest stay hashes.
- No observed resource used a graphics page, so that path is untested against
  real data.
- Semantics. The decoder reports storage, not meaning: a field means what its
  document family says it means, and that has not been established for any
  field of any family.

## Deliberately out of scope

Exporter and website schema changes, committed game-derived tables, general
metadata name discovery, `PSIN`/`LSCH` block interpretation, and the `PMAP`
family's instance data.
