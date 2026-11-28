# RBF0 metadata decoding

RBF0 is the second metadata encoding a type 11 row can hold. This document
describes how Leonida Forge decodes it, where the code lives, and what the
decoder was validated against. The format itself is specified in the research
repository (`formats/metadata/rbf0`); this document is about the implementation.
The third form, the `0DRP` resource, has its own document (`odrp.md`).

## Where the code lives

| Layer | Path | Responsibility |
| ----- | ---- | -------------- |
| Grammar and model | `crates/rage9/src/rbf0/mod.rs` | Header, tokens, limits, errors, `decode`/`parse` |
| Document tree | `crates/rage9/src/rbf0/tree.rs` | `Document`, `Element`, `Node`, `Field`, `Attribute`, `Value`, `Text` |
| JSON and XML views | `crates/core/src/rbf0.rs` | `document_json`, `document_xml`, `counts` |
| Shared metadata API | `crates/core/src/metadata.rs` | One `Document` over PSIN and RBF0, chosen by signature |
| CLI | `apps/cli/src/inspect.rs` | `--metadata-output`, `--metadata-xml` |
| Desktop | `apps/desktop/src/viewers/metadata` | The existing Metadata Viewer |
| Validation harness | `crates/rage9/examples/rbf0_population.rs` | Decodes every reachable payload and tallies outcomes |

The decoder exists once. The CLI, the desktop and the exporter drive the same
`lforge_core::metadata` API; none of them parses RBF0 itself.

## The document model

`rbf0::decode` returns a `rbf0::Document`. It keeps the document as the bytes
describe it:

- `names` — the document's own name table, in definition order, with the offset,
  length and SHA-256 of each definition.
- `root` — an `Element`, which holds its 12-bit name index, the `u32` reserved
  word, its counted `attributes`, its `children` in document order, and the
  offsets its token starts at and its terminator ends at.
- Children are a `Node`: a nested `Element`, a `Field` (a value in a body
  position) or a `Text` node.
- A `Value` is one of four forms: `Number` (classes 1 and 4, with the bytes the
  token stores), `Zero` (classes 2 and 3, no bytes), `Fixed` (class 5, twelve
  bytes) or `Bytes` (class 6, a declared length and its bytes).

Nothing is renamed and nothing is inferred that the bytes do not carry. The two
number classes expose the reading the population establishes —
`Value::integer` for class 1 and `Value::float` for class 4 — while `bytes()`
stays available on every value, so a caller can always work from the payload
rather than from the reading.

Text is kept as stored. `Text::text` splits the one trailing NUL a text node
carries and reports whether it was there; `Value::text` splits nothing, because
a length-prefixed value carries no terminator, so a NUL it ends with is part of
the value. Bytes that are not UTF-8 are reported as hex rather than lossily
decoded. A name that is not UTF-8 is absent from the name table rather than
empty, and its definition keeps the length and digest of the bytes it read.

### Numbers a consumer cannot hold

Class 1 yields `integer`, the two's-complement reading as `unsigned`, and, past
2^53 − 1 where a JSON number stops being exact, `integerText` with the exact
digits. Class 4 yields `float`, or `float: null` beside `floatText` of `NaN`,
`Infinity` or `-Infinity`. A value whose bytes a read limit dropped carries
`omitted: true` and its declared length, never an empty string.

The validated population reaches none of the last three cases: its class-1
integers span −2,125,891,426 to 4,289,044,108 and all 39,291 class-4 doubles are
finite, so `integerText` and `floatText` are exercised by the unit tests alone.
The `unsigned` reading does appear in exports.

### Decoding status

`Document::status` is one of three:

| Status | Meaning |
| ------ | ------- |
| `decoded` | The root element ended the payload |
| `partial` | The root element decoded, but bytes follow it (`trailing` counts them) |
| `failed` | The parse stopped; `failure` names the kind, the stage, the offset and the reason |

A failure never discards what was already read. The parser keeps open elements
on an explicit stack, so a body it cannot follow closes them where it stopped
and returns the tree it reached.

### Limits

`rbf0::Limits` bounds one parse: `max_depth` 256, `max_names` 4096,
`max_elements` 2²⁰, `max_value_len` 1 MiB and `max_text` 8 MiB of kept name,
text and value bytes. Every read is bounds-checked and every length is checked
against the bytes that remain before it is used, so a hostile payload cannot
allocate more than the limits allow or overflow an offset.

The depth cap is 256 because the population nests to 35 and a cap of 32 refused
four real payloads. A limit that real documents exceed is a bug in the limit.

## Shared metadata API

`lforge_core::metadata::decode` reads a payload and returns
`metadata::Document::{Pso, Rbf0}` from the payload's signature. The enum exposes:

- `format()` — `pso` or `rbf0`.
- `status()` — the decoding status in one vocabulary for both formats.
- `summary()` — a one-line statement of what the document holds.
- `counts_json()` — counts in a shape both formats share.
- `document_json(names, sample)` — the whole document.
- `document_xml(source)` — the whole document, with provenance.
- `schema()` — `leonida-forge.psin-document/1` or
  `leonida-forge.rbf0-document/1`.

The PSIN representation is unchanged: its hashes stay the identity and a name
table only ever adds candidates beside them. RBF0 keeps the names the payload
stores. Neither format is flattened into the other's shape, and existing PSIN
consumers read exactly what they read before.

## CLI

RBF0 uses the metadata workflow PSIN already had; there are no RBF0-specific
commands.

```text
lforge archive inspect <archive> --enter row:N --row R --metadata-output doc.json
lforge archive inspect <archive> --enter row:N --row R --metadata-output doc.xml --metadata-xml
```

`--enter` reaches a nested archive, `--row` selects the row, and the canonical
resource path in `source.resource` is unchanged by the format. The export names
its format and status in `source`, and the document carries the format's own
schema id, so an RBF0 export is never mistaken for a PSIN one.

`lforge archive inspect` without `--metadata-output` reports the same summary it
always has: header form, name count, element count, depth, value tokens per
class, string statistics and name digests. It does not print names or text.

## Desktop

`opens_as_metadata` accepts a classification whose `format_id` is `psin`, `rbf0`
or `meta-resource`, and the metadata arm stays ahead of the text arm, so a
payload this build reads structurally is never claimed by the byte-level text
check.

The Metadata Viewer decodes either format into the same rows:

- an element row per element, with its name, attribute count and child count,
  expanding into its attributes and then its body in document order;
- attribute rows prefixed `@`, a value row per named value, and a `text` row per
  text node;
- a `name table` group listing the document's definitions, showing a name that
  is not UTF-8 as such rather than as an empty entry;
- a `notes` group for the decoder's diagnostics, and a warning row when the
  parse stopped or bytes follow the root element.

Rows stay bounded (`MAX_ROWS` 200,000, 512 children per element) so a 68,000
element document opens without stalling the window. Filtering, collapsing,
keyboard selection and copy work as they do for PSIN. The status line reports
`N names in the document` for RBF0 where it reports `N hashes named` for PSIN,
because the two formats name themselves differently.

The Binary Inspector still opens the same payload as bytes through File → Open,
and the Text Viewer stays reserved for payloads that are text.

## Validation

`crates/rage9/examples/rbf0_population.rs` walks archives the way the CLI does,
decodes every payload whose first four bytes are the magic, and tallies the
outcomes. It writes no document out and prints no name unless asked.

```text
cargo build --release -p lforge-rage9 --example rbf0_population
target/release/examples/rbf0_population "<GAME_ROOT>/data.rpf" \
    --executable "<GAME_ROOT>/<game executable>" --recursive --values
```

`data.rpf`, exhaustive:

| Measure | Result |
| ------- | ------ |
| Archives entered | 41 |
| Entries walked | 23,075 |
| Payloads beginning with `RBF0` | 1,462 |
| Payloads decoded to the end of the root element | 1,462 |
| Unreadable payloads | 0 |
| Failures and limit refusals | 0 |
| Distinct payloads by SHA-256 | 1,395 |
| Sizes | 98 to 2,372,401 bytes |
| Elements per document | 1 to 68,398 |
| Deepest nesting | 35 levels |
| Headers | 1,459 versioned, 3 versionless |
| Text nodes | 287,297, of which 287,267 end with the NUL the format carries |
| Length-prefixed values | 110,051, none terminated |
| Payloads with a note | 27, all for the 30 text nodes that are not UTF-8 |

The other archives of the installation were walked under a per-archive entry
bound of 60,000. `audio.rpf` was not walked: it stores audio streams and holds
no type 11 rows in the earlier census.

| Archive | Entries walked | RBF0 | Decoded |
| ------- | -------------: | ---: | ------: |
| `data.rpf` | 23,075 | 1,462 | 1,462 |
| `common.rpf` | 418 | 0 | 0 |
| `script.rpf` | 1,016 | 0 | 0 |
| `appdata0.rpf` | 2 | 0 | 0 |
| `shaders.rpf` | 3 | 0 | 0 |
| `movies.rpf` | 515 | 0 | 0 |
| `textures.rpf` | 1,387 | 1 | 1 |
| `packs.rpf` | 60,000 (bound) | 0 | 0 |
| `navmeshes.rpf` | 60,000 (bound) | 0 | 0 |
| `anim.rpf` | 54,947 (bound) | 1 | 1 |
| `levels.rpf` | 49,015 (bound) | 0 | 0 |
| `pack/core_bvh4` | 60,000 (bound) | 0 | 0 |
| `pack/core_restofworld` | 1,156 | 3 | 3 |
| `pack/core_restofworld001` | 28 | 0 | 0 |
| `pack/core_licenses` | 6 | 0 | 0 |
| `pack/shared_minigame000` | 3,183 | 0 | 0 |
| `pack/shared_minigame000_bvh4` | 1,331 | 0 | 0 |
| `pack/story000_script` | 3,072 | 0 | 0 |
| `pack/story000_bvh4` | 4 | 0 | 0 |
| `pack/story000_restofworld` | 507 | 0 | 0 |

296,590 entries were walked outside `data.rpf` and 5 RBF0 payloads were found,
all of which decoded. RBF0 is effectively a `data.rpf` format in this
installation. The six bounded walks are a floor, so the five is a floor too.

Automated tests cover the decoder, the two views and the two front ends:
synthetic documents with nested elements, every value class, unterminated and
truncated bodies, an unknown token class, a name index beyond the table,
excessive nesting, an oversized value, a trailing payload, canonical identity
in the export, and the viewer's row building, filtering and status.

Desktop validation is visual for the first frame and automated for the rest.
Three resources were opened in the Metadata Viewer on this machine and the
window captured: the reported `data.rpf` UI document (30 elements, 187 rows),
the PSIN document of `data.rpf` row 41 (124 structures, 5,824 rows) and the
largest RBF0 payload of the installation (68,398 elements, 130,968 rows). Each
painted its root, its children and its values.

Before that check the viewer painted an empty content area with a correct
toolbar and status bar: the list sat in a block-level container, where its
flex sizing means nothing, so it measured no height. That is fixed and covered
by `content_area` and row tests, but the fix itself is only observable in a
rendered window.

What remains unverified by hand: clicking a row to fold it, typing in the
filter, and the Copy Row button. Their logic is covered by tests; no mouse or
keyboard interaction was performed in this change.

## Name discovery

The census vocabulary was compared against the 32-bit name hashes thirteen
`PSIN` documents store, using the case-sensitive hash both formats are known
to use for schema names:

| Measure | Result |
| ------- | ------ |
| PSIN documents | 13 |
| PSIN name hashes stored | 1,092 |
| Distinct RBF0 names | 2,539 |
| Hashes reproduced | 16 (14 fields, 2 enum values) |

The reproduced names are the generic ones the two formats share — names such as
`Name`, `Type`, `Value`, `Data`, `Conditions` — and no structure name was
reproduced. A hash equality is a candidate, not a proof, because a 32-bit hash
collides.

So RBF0 text is a real but small source of `PSIN` name candidates: it
contributes the shared field vocabulary, not the schema names. The harvest that
already reads RBF0 as verified text (`lforge names`) is unchanged and still the
right place for a broader attempt.

## Exporter-relevant findings

What the decoded population holds, and what it does not:

- It is UI and tuning data. The 30 root families are prefab definitions, screens,
  animation node graphs, credits pages, movie subtitle containers and views,
  flow blocks, feedback contexts, layout containers and parameter blocks, plus
  two tuning documents. A document is a typed object graph: 184 of the 2,539
  distinct names and values carry the engine's `__` class separator, so a
  document states the type of the object it describes.
- Numbers are ids, counts and enumeration values on the integer side and layout
  metrics on the double side. The only twelve-byte form, class 5, was not
  observed in this population, so no vector-shaped value was seen.
- Resource relationships exist but are rare: 4 of the 2,035 distinct
  length-prefixed values are relative asset paths. A document mostly references
  other documents and engine types by name, not by path.
- The population carries no vehicle, ped, weapon, clothing, model or texture
  metadata. RBF0 therefore adds nothing to the exporter's current asset classes
  from `data.rpf`.

Concrete opportunities for a later task, none of them implemented here:

1. A UI catalogue export: screens, prefabs and their layout parameters are
   fully decoded now and could be published as a UI asset class with a schema of
   its own. That is a new exporter schema and is out of scope for this change.
2. Tuning documents: the two tuning payloads decode to named values and could
   join the existing tuning extraction once their field meanings are checked.
3. A name-hash dictionary: the `__` class names and the element names measured
   above are candidate keys for `PSIN` schemas, which is the measured overlap in
   the previous section.
4. Nothing here should be mapped speculatively. A field means what its document
   family says it means, and that has not been established for any field.

## Remaining limits

- Type 2 and type 3 values store no bytes. Their meaning cannot be recovered
  from the document.
- The meaning of a value's number or text is not established. The decoder
  reports storage, not semantics.
- A text node is shown as text only when it is UTF-8; 30 of the 287,297 are not.
- A payload larger than the caller's read bound is refused rather than opened.
  The CLI reads whole payloads, so a metadata document above `MAX_METADATA`
  stays unreadable by that path.
- Token classes 7 to 14 were not observed. A payload with one stops the parse
  and keeps what came before it.

## Deliberately out of scope

Decoding of `PSIN`/`PMAP` instance data, undefined `PSIN`/`LSCH` block
interpretation, general metadata name discovery, and any exporter or website
schema change.
