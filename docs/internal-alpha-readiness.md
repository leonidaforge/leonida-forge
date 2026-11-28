# Internal Alpha readiness

Scope: the Windows desktop explorer, its export workflow and the Windows x64
package for an internal, recovery-focused Alpha. Date: 2026-11-26.

## Verdict

A recovery-focused internal Alpha is ready to hand to testers as an install-free
ZIP. The scan-recovery, inspect and export pipeline works in automated tests and
against the real archives recorded below. The packaged desktop binary starts on
this Windows 11 machine and its window responds.

Full native encrypted RPF9 support is not ready and remains under research. A
processed table of contents is read only after its signature verifies against a
local game executable that the user selects, and no key material is extracted or
stored. Without such an executable the tools refuse native metadata instead of
guessing, and scanning stays the fallback.

Public publication is not approved. No GitHub Release is created and no tag is
pushed.

## Supported functionality

- Browse folders, RPF9 and ZIP archives as one tree. Archives are recognised by
  content, not extension. Nesting works up to 8 levels.
- Recover entries from encrypted RPF9 archives by scanning for zlib streams.
  Group them by kind, name them by archive offset, and report completeness.
- Reconstruct RAGE resources from consecutive page streams, with page-level
  inspection.
- Read native RPF9 entries where the table of contents is stored unencrypted:
  stored bytes, raw DEFLATE, chunked payloads, and companion-file payloads.
- Read a processed table of contents after authenticating it against a local
  game executable selected in the explorer. Native rows keep their row number
  and name hash, and are never merged with recovered entries.
- Show a native row's name from the embedded LUTs, from a `rpf9-hash64.lut` or
  `rpf9-key32.lut` beside the executable, or from a `<archive>.names.txt` table
  next to the archive. A name is marked verified only when hashing reproduces
  the stored key. Unresolved and ambiguous rows use the stored key in canonical
  hexadecimal form as the visible label. Names are display data; the row number
  and stored hash remain authoritative.
- File a row under the folders its verified relative path describes, without
  changing its row number or path identity. Unsafe components (absolute paths,
  `.`, `..`, empty, drive letters, refused characters) never create folders.
  Rows without a usable path are listed last in `Unnamed Entries`. A native
  archive can also be listed as one flat list of all its rows; the choice is
  stored in settings and re-lists from the in-memory table of contents.
- Filter the current listing by visible label, stored name hash or key, and
  type, without indexing the archive.
- Index native hashes, harvest candidate strings from readable payloads and the
  local executable, and export validated LUT files with `lforge names`.
- List, search and export deterministic manifests of authenticated native rows
  with `lforge archive ls`, `search` and `manifest`. Revalidate the bundled LUTs
  and compare them with a Research checkout with `lforge names audit`.
- Inspect any file as bytes in the Binary Inspector, including files inside
  archives.
- Inspect a recognised file format from its contents, in the Binary Inspector and
  with `lforge binary inspect` and `lforge archive inspect`. Both front ends use
  the same recogniser in `lforge-core`. The RDS5 container reports its header,
  record array, ETPF chunk extent, block catalogue, block storage classes and
  per-element descriptor values; `binary inspect --texture` reconstructs one
  element's bytes and reports its components, and the Binary Inspector shows the
  first element's chain; an RBF0 document reports its token stream, object tree,
  name dictionary and string and attribute value counts and lengths; a GFx
  version-42 container reports its header, extent, frame fields and tag walk; a
  PSIN payload reports its section walk, family, descriptor or block table,
  section table, body structure and checksum; an EDUP payload reports its entry
  framing and opaque trailing blob; an ADAT payload reports its header, tables,
  chunk records, packet framing, block classes, rate values and position table;
  a KB2 container reports its header, frame index checks and audio record
  counts. RPF9 is recognised by signature only.
  `archive inspect --enter` follows mixed ZIP/RPF9 nesting, and a row or ZIP
  entry is decoded in memory, so nothing is extracted to inspect it.
  `archive resource --drawable` walks the drawable structure of a reconstructed
  resource: header fields, LOD slots, models, geometries, bounds arrays, vertex
  buffer and declaration arithmetic, index counts and the shader group's
  parameter hashes and slot states. `archive resource --dictionary` reads the
  reconstructed system segment as a texture dictionary, record by record.
- Open a drawable or a texture in its own window. The model viewer decodes the
  highest populated LOD, resolves embedded and external textures by exact
  64-bit key, frames the geometry and reports geometry and texture
  completeness. A fragment opens in the same viewer: its member drawable is
  listed as one component with per-mesh visibility toggles, and the diagnostics
  say when only part of the fragment is assembled. Only the member drawable the
  fragment root references is assembled; a fragment root that also reads as a
  resource-level drawable reports the overlap instead of hiding it.
- Open a drawable dictionary in its own window: the member list shows every
  member with its name, name hash and state, and the selected member decodes
  into the viewport. One member load runs at a time, one selection waits behind
  it, and the newest selection wins, so rapid switching cannot queue work or
  land an older result. Multi-drawable fragments and skeleton-driven placement
  are not identified.
- Inspect the skeleton a drawable carries: the panel lists every bone with its
  hierarchy, a name, index and key filter, the selected bone's metadata and the
  meshes it is associated with. The overlay is off until the toggle is pressed,
  rows are virtualized so a 596-bone skeleton stays reachable, and hiding the
  meshes restores the per-mesh choices when they come back. A dictionary member
  keeps its own skeleton state.
- Export one entry to a chosen path, from the entry context menu and the File
  menu. Native entries, recovered entries, resource pages, regions and ZIP
  entries decode through one path.
- Export safety: bytes stream to a temporary file in the destination directory
  and move into place only after the whole payload decodes. A failed or
  cancelled export leaves no partial final file. The source and its companion
  are revalidated when export begins.
- Open a metadata container or a text payload in its own window. A `PSIN`
  container opens in the metadata viewer: the tree walks the schema and the
  instance blocks, a row expands and collapses, a filter keeps the rows that
  match and the ancestors that hold them, and a row copies as text. The stored
  hash stays the identity and a resolved name is shown beside it. The same
  viewer opens an `RBF0` payload and a `0DRP` metadata resource, each through
  the shared metadata API. A payload the classification reads as text opens in
  the text viewer instead, so a metadata container is never claimed by a
  byte-level text check: metadata payloads carry thousands of zero bytes in
  their first 64 KiB, and the text check refuses any payload containing one.
- The window names the resource by its canonical path, the same string the CLI
  reports, so a row inside a nested archive shows the whole chain and never the
  temporary file it was decompressed into.
- The `.zmt` population the archives on disk reach is 865 rows, counted by
  outcome: 837 carry the `PSIN` signature, of which 686 decode completely, 89
  keep at least one block whose type no structure or pool defines, and 62 are
  the `PMAP` family; 27 are `RBF0` payloads and 1 is the `0DRP` resource form.
  None is text. The counts are exhaustive for that population and say nothing
  about the 4,664 `.zmt` rows inside archives stored in `data.rpf`, which a
  recursive search reaches but which were not decoded when this was written.

## Unsupported functionality

- Extracting key material from the game executable, or authenticating native
  metadata without a compatible local executable. Without one, or when the
  signature does not verify, an encrypted archive falls back to scan recovery.
- Original names and folder structure for recovered entries. Names are archive
  offsets; grouping is by detected kind.
- Any format whose structure is not documented. RDS5 blocks of the six storage
  classes that are not `0x20` zlib or `0x00` stored are reported and never
  decoded; the RBF0 token classes that were not observed stop the parse, and the
  meaning of every name, the header words and the attribute position is unknown;
  GFx tag bodies are opaque; the ETPF entry fields, the ETPF region after the
  entry table and the upper half of the RDS5 block counter are not interpreted.
- Semantic decoding. PSIN gives no tag, field, block or value a meaning; EDUP
  does not scan a texture store and keeps its trailing blob opaque; ADAT names no
  codec, decodes no audio and does not materialise packets; KB2 decodes no frame
  and names no codec; texture dictionaries expose their records but decode no
  pixel and resolve no texture reference.
- Metadata containers whose instance data is not decoded still open, and say so.
  A `PMAP` container carries the `PSIN` signature, so it opens in the metadata
  viewer, which reports the `PMAP` family and that its instance data is not
  decoded; the bytes stay reachable through File → Open in Binary Inspector.
  An `RBF0` payload and a `0DRP` resource are not metadata containers; they do
  not carry the `PSIN` sections. Both are recognised by signature and decoded
  into the metadata viewer, which reports the form it read.
  A block whose type names neither a structure nor a pool keeps its bytes and
  is reported as unsupported rather than guessed at.
- Vertex semantics. A drawable's bounds, layout codes, declaration bytes, index
  descriptor fields and material parameter values are reported as stored values.
  No vertex position, triangle, mesh or texture reference is reconstructed, and
  the graphics base is reported only when two distinct pointers support it.
  The 58 header-union exceptions observed in the research remain unexplained; a
  difference there is reported and does not invalidate the drawable.
- Resource-level inspection in the desktop. The Binary Inspector covers the
  payload formats by content, but the explorer has no resource viewer that
  reconstructs a resource's two segments, so dictionary, drawable and RDS5
  element inspection stay on the CLI. The blocker is the missing segment-aware
  resource view, not the parsers, which are shared.
- Virtual folder grouping from resolved native paths. The native list is flat;
  path-like candidate names are display data and do not become directories.
- Payload transforms are decoded when the executable that authenticated the metadata provides the algorithm-`0x11` key state; a stream shape the trial decoder cannot verify is refused. Compression modes beyond stored, raw DEFLATE and chunked zlib or copied chunks are refused.
- Writing to game files. All file access is read-only by design.
- Skeleton-driven behaviour. A decoded skeleton is shown as stored: the viewer
  does not skin geometry, blend influences, play or blend animation, pose or
  edit bones, and does not place geometry by a bone transform. A skeleton with a
  non-identity bone scale is reported as unsupported rather than drawn.

## Export request handling

A save dialog takes the single export slot before it opens. A request holds the
slot while its dialog is open or while its export runs. A second Save As
request is refused while the slot is held, so two dialogs cannot overlap and a
delayed dialog completion cannot replace a running export.

`run_export` rechecks the slot when the dialog returns. A request that was
cancelled, or whose generation no longer owns the slot, writes nothing. The
slot is released on success, failure and dialog cancellation, so a refused or
cancelled request cannot leave Save As disabled. The existing export task and
its cancellation handle stay untouched; a late request never overwrites them.

### Suggested filenames

Recovered RPF9 entries and native table-of-contents rows use identifiers
generated from an archive offset or row number. A ZIP entry has its own name,
which comes from the archive. That name is passed to the save dialog as a
suggestion only. The destination is whatever the dialog returns, and no entry
name is joined to a path to build a destination. ZIP names that escape the
archive root are skipped when the archive is listed.

## Real-data evidence

Read-only smoke tests ran during the earlier readiness assessment against three
sample archives from a locally configured GTA VI directory, through the CLI,
which shares the decode path with the desktop. Only aggregate outcomes are
recorded here. They were not repeated for this package.

- Tiny archive (8.8 KB): 0 recoverable entries, 1 unrecovered region. Handled
  without error; reported as not necessarily empty.
- Mid archive (6.6 MB): 277 entries from 954 streams across 55 regions, of which
  257 were complete XML and 20 were unverified text or binary.
- Mid archive (4.3 MB): 1013 entries, of which 1012 were complete PSIN payloads.
- Export of a complete recovered XML entry wrote exactly the declared decoded
  size and produced valid XML.
- Export of an unverified entry wrote the declared size and printed a caveat
  that the bytes may be whole or partial.
- Overwrite was refused without the overwrite flag and succeeded with it.
- Native metadata on an encrypted archive reported the encryption diagnostic
  (static pass required, cipher type 16, key unavailable) and marked every
  entry unavailable. Native extraction refused the archive and wrote no file.
- A non-existent recovery id produced a clear error and no output file.

A recursive classification census of `data.rpf` ran for this review against the
same installation, through the CLI, which shares the decode and classification
path with the desktop. `archive census data.rpf --recursive --entries` opened 42
archives, enumerated and probed all 23,075 entries and finished with
`completion.complete = true`, no failed archive and nothing stopped by a limit.
Classified from the decoded head only, 5,321 of those entries are the metadata
resource type, in 31 of the 42 archives: 2,573 carry the `PSIN` signature, 1,462
are `RBF0` payloads and 1,286 are the `0DRP` resource form. The census counts
what each entry is; it does not deserialize a metadata document, so a `.zmt` row
it calls `psin` may still hold either `PSIN` family.

The metadata decoders were validated separately, over every payload the
signature finds rather than over the head classification. An exhaustive walk of
`data.rpf` decoded all 1,462 `RBF0` payloads and all 15,768 `0DRP` resources;
the resource walk enters nested archives, so it also reaches the 14,482 type 111
rows the census's type 11 count does not name. 15,767 resources decode to their
full extent and one is partial, for four blocks no structure, pool element or
established width describes. No reference fails to bind and no read limit is
reached. `docs/formats/rbf0.md` and `docs/formats/odrp.md` state the details.

## Test coverage

Automated, run for this package:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass.
- `cargo test --workspace --locked`: 1,426 tests pass across the binary, core,
  rage9, renderer, CLI and desktop crates, including unit, integration and doc
  tests.
- `cargo build --workspace --locked`: pass.
- Release build for `x86_64-pc-windows-msvc`: pass.
- Packaged binary scan for the build user's profile path and the repository
  root: no matches.

The export slot is covered by focused unit tests: overlapping dialog requests,
a cancelled dialog whose result arrives late, and a delayed dialog completing
while an export runs. The tests assert that a losing request never writes its
destination and never takes the slot from a running export.

The CLI export and metadata paths have integration tests. The desktop export
file writer has tests for success, overwrite, cancellation, a missing companion
and a failed finalisation.

Manual, for this package: the packaged desktop launched on this Windows 11
machine and opened a top-level window titled `Leonida Forge`, with no
missing-runtime dialog. The process stayed alive until the test harness stopped
it. No window interaction was performed, so responsiveness to input is not
verified. This machine has the Visual C++ Redistributable, so it is not a
clean-machine test.

## Known limitations

- The desktop export flow has no automated GUI test. The slot decisions are
  unit tested, but the GPUI wiring, the save dialog, the toast lifecycle and
  the menu gating need a manual pass.
- The 3D viewport and renderer demo are out of scope for a recovery Alpha. The
  renderer demo is a debug-only tool.
- A recovered entry can be partial or unverified. The status is shown, and an
  export keeps the caveat, but the bytes are not proof of an original file.
- A metadata container is read into memory before it is decoded, so a decoded
  container larger than the 64 MiB materialisation cap is refused with the
  existing message rather than opened. The largest decoded container observed
  is 17,406,784 bytes.
- The metadata viewer is not covered by a GUI test. The tree, the routing rule,
  the canonical window title and the decoder are unit tested; the rendered
  window was not inspected interactively.

## User-visible failure behaviour

- A decode or I/O error during export shows a failure toast that stays until
  dismissed and names the reason. No partial final file is written.
- Cancellation removes the toast and writes no file.
- A completed export shows a neutral success toast that clears itself after a
  few seconds. The message never claims recovered bytes are an original file.
- Only one export request is active at a time. A save dialog holds the slot, so
  a second request is refused while the dialog is open or an export is running.
- Opening an archive shows the current step and offers cancellation instead of
  blocking. A processed table of contents is authenticated in the background,
  and the archive explains whether it needs an executable or failed
  authentication, with a way to select one or recover by scanning.

## Packaging decision

The Windows x64 Alpha ships as one ZIP with the two executables, the GPL text,
a short README and the third-party component list. It contains no installer,
updater, game files, research files, PDBs or build directory.

Artifact names:

- `leonida-forge-0.1.0-windows-x64.zip`
- `leonida-forge-0.1.0-windows-x64.zip.sha256`

ZIP contents:

```text
leonida-forge-0.1.0-windows-x64/
  leonida-forge.exe
  lforge.exe
  LICENSE.md
  README.md
  THIRD-PARTY-NOTICES.md
```

The checksum file has one line, with lowercase hexadecimal SHA-256, two spaces
and the ZIP filename:

```text
<sha256>  leonida-forge-0.1.0-windows-x64.zip
```

The third-party list is generated from the packages in the Windows x64 normal
dependency graph. It records names, versions, declared licenses and source
repositories. A public release still needs a full license-text audit.

## Runtime linkage

Both binaries use the static MSVC CRT. `scripts/build-windows-x64.ps1` passes
`-C target-feature=+crt-static` through `CARGO_ENCODED_RUSTFLAGS`. This is the
Rust-supported `crt-static` target feature. The repository does not set it
globally, so development, clippy and test builds keep the default dynamic CRT
and match CI.

The same script remaps the repository root, `CARGO_HOME` and `RUSTUP_HOME` to
`/leonida-forge`, `/cargo` and `/rustup`. Release binaries carry panic-location
strings, and without the remap they would embed the build machine's user name
and paths. The remap also makes the path strings stable across machines.

`dumpbin /dependents` on the release binaries shows no `VCRUNTIME140.dll`, no
`MSVCP140.dll` and no `api-ms-win-crt-*` imports. The remaining imports are
Windows system DLLs, including `kernel32.dll`, `user32.dll`, `ole32.dll`,
`d3d11.dll`, `dcomp.dll`, `dwrite.dll` and `icuuc.dll`. No Visual C++
Redistributable is required.

`dumpbin /headers` reports machine `8664` for both. The desktop uses subsystem
2 (Windows GUI) and the CLI uses subsystem 3 (Windows CUI).

## Reproducible build

Requirements: Windows 11 x64, rustup, Visual Studio Build Tools with the
Desktop development with C++ workload and a Windows SDK. The toolchain is
pinned by `rust-toolchain.toml` and dependencies by `Cargo.lock`.

```powershell
rustup toolchain install
pwsh -NoProfile -File scripts/build-windows-x64.ps1
pwsh -NoProfile -File scripts/package-windows-x64.ps1
```

The first build fetches GPUI from the pinned Zed revision, so a clean machine
needs network access. The build script sets the static CRT and the path remap.
The package script verifies both executables, their PE machine and subsystem,
the absence of dynamic CRT imports, and that the CLI answers `--help` and
reports the expected version. It then stages only the listed files, writes the
ZIP and prints the SHA-256.

## GitHub Actions workflow

`.github/workflows/windows-alpha.yml` is manual (`workflow_dispatch`) and uses
`windows-2025`. It checks out the selected commit, installs the pinned
toolchain, then runs the CI gates: fmt, clippy, tests and the locked workspace
build. It then runs the release build script, runs the packaging script, and
uploads only `dist/*.zip` and `dist/*.sha256` with
`actions/upload-artifact`. Workflow permissions are limited to
`contents: read`. There are no deployment secrets, no external services and no
GitHub Release step. Tag triggers and release publication remain disabled until
explicitly approved.

## Manual validation checklist

Run on a clean Windows 11 x64 machine or VM without Visual Studio or the Visual
C++ Redistributable installed.

1. Copy the ZIP, verify its SHA-256 against the checksum file, then unpack it
   into a folder with no game files.
2. Start `leonida-forge.exe`. Confirm there is no missing-runtime dialog and
   that the window appears.
3. Use **File > Open Folder** to open an ordinary folder. Confirm files and
   folders are listed and navigation works.
4. Open a ZIP archive and browse its folders. Export one entry and compare the
   decoded bytes with a known-good extraction.
5. Open an RPF9 archive with unencrypted table-of-contents metadata. Confirm
   native entries are listed and one readable entry exports correctly.
6. Open an encrypted retail RPF9 archive without an executable selected.
   Confirm the archive asks for an executable or for recovery, and that
   choosing recovery shows indexing progress and grouped candidates.
7. With a compatible local executable selected through **File > Select Game
   Executable…**, open the same archive again. Confirm native rows are listed,
   the metadata status says the signature verified, and one readable row
   exports. Then clear the executable and confirm the archive no longer lists
   native rows. Place a `<archive>.names.txt` with a known candidate path next
   to the archive, reopen it, and confirm the row moves under the folders its
   path describes while its stored hash and path stay. Remove the file and
   confirm the names return to unknown. Then copy `rpf9-hash64.lut` beside the
   executable, reopen the archive, and confirm the resolved names become
   folders and labels, with `Unnamed Entries` last and `Row NNNNN` still each
   path.
8. Browse `Recovered Entries`, `Resource Pages` and `Unrecovered Regions`.
   Confirm offsets, sizes and completeness text are plausible.
9. Open a plain file and an entry inside an archive in the Binary Inspector.
   Check the signature, size and search.
10. Export through the entry context menu, then through **File > Save Selection
    As**. Confirm the suggested name, destination folder and result toast.
11. Save to an existing file. Confirm the save dialog asks before replacing it,
    and that cancelling the overwrite leaves the old file unchanged.
12. Cancel an export while it runs. Confirm no new or partial file is left.
13. Start a second export while the first save dialog is open, then while the
    first export is running. Confirm Save As is disabled in both cases, that
    cancelling the dialog re-enables it, and that finishing or failing the
    export re-enables it again.
14. Run `lforge.exe --help`, `lforge.exe info`, and `lforge.exe archive info`
    on an RPF9 archive.
15. Run `lforge.exe archive recover <archive> --list`, then export one
    candidate. Confirm overwrite protection and the unverified-bytes note.
16. Inspect a PSIN, EDUP, ADAT and KB2 payload with `lforge.exe binary inspect`
    and in the Binary Inspector. Confirm each report names its family or
    variant, and that no codec, pixel, frame or field meaning is claimed.
17. On a resource whose system segment is a texture dictionary, run
    `lforge.exe archive resource <archive> <id> --dictionary` and
    `--dictionary --record 0`. Confirm the records, extents and name checks.
18. On a drawable resource, run `lforge.exe archive resource <archive> <id>
--drawable`. Confirm the bounds, index counts, declaration entries and
    material slot states, and that no vertex position or triangle is produced.
19. Check that `%APPDATA%\Leonida Forge` holds settings and the archive index,
    and that no game file changed.

Record which steps ran, the Windows build, the GPU and any archive samples used.
Do not put game files in the package or the repository.

## Remaining blockers

For the internal Alpha, none. The package is ready to hand to testers.

Capabilities awaiting real-data acceptance, because this build's checks used
synthetic fixtures only:

- The corrected raw-continuation resource reconstruction, and the archive
  information path across the affected resources.
- Texture dictionary recognition and record parsing on the sampled population.
- The extended drawable walk on the two documented samples.
- PSIN `LSCH` and `PMAP` payloads, EDUP tables, ADAT variants and KB2 rows.

Semantic decoding is blocked on research, not on application work: texture pixel
format, texture-reference selection among equal hashes, mesh and material
rendering, and audio and video decoding. None of these is scheduled.

Still required before a public prerelease:

- Complete the clean-machine checklist above, including the desktop interactions
  that have no automated test.
- Decide the supported RPF9 claim. Native metadata needs a compatible local
  executable, so public text must describe both authenticated native listing and
  the recovery fallback.
- Add an application icon, version resource and manifest if the desktop is
  published outside the internal group.
- Complete a third-party license-text audit for every bundled component.
- Add a tag-triggered prerelease workflow only after publication is approved.
