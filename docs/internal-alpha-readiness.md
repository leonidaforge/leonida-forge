# Internal Alpha readiness

Scope: the Windows desktop explorer and its export workflow, assessed for an
internal, recovery-focused Alpha. Written for maintainers deciding whether to
cut a prerelease. Date: 2026-11-24. Baseline commit: `e8ffd2b` plus the export
fix recorded in this branch.

## Verdict

A recovery-focused internal Alpha is ready, with the limitations below. The
scan-recovery, inspect and export pipeline works end to end on real encrypted
RPF9 archives and is honest about what it recovered.

Full native encrypted RPF9 support is not ready and remains under research. The
table-of-contents decryption key is not available, so the tools refuse native
entries instead of guessing. This is correct behaviour, not a defect.

A Windows x64 prerelease could reasonably be distributed internally once the
packaging items below are settled. No release workflow exists yet, by design.

## Supported functionality

- Browse folders, RPF9 and ZIP archives as one tree. Archives are recognised by
  content, not extension. Nesting works up to 8 levels.
- Recover entries from encrypted RPF9 archives by scanning for zlib streams.
  Group them by kind, name them by archive offset, and report completeness.
- Reconstruct RAGE resources from consecutive page streams, with page-level
  inspection.
- Read native RPF9 entries where the table of contents is stored unencrypted:
  stored bytes, raw DEFLATE, chunked payloads, and companion-file payloads.
- Inspect any file as bytes in the Binary Inspector, including files inside
  archives.
- Export one entry to a chosen path, from the entry context menu and the File
  menu. Native entries, recovered entries, resource pages, regions and ZIP
  entries decode through one path.
- Export safety: bytes stream to a temporary file in the destination directory
  and move into place only after the whole payload decodes. A failed or
  cancelled export leaves no partial final file. The source and its companion
  are revalidated when export begins.

## Unsupported functionality

- Decrypting the native RPF9 table of contents. The static pass uses a cipher
  whose key is not available, so encrypted archives fall back to scan recovery.
- Original names and folder structure for recovered entries. Names are archive
  offsets; grouping is by detected kind.
- Payload transforms and compression modes beyond stored, raw DEFLATE and
  chunked zlib or copied chunks. Entries that need anything else are refused.
- Writing to game files. All file access is read-only by design.

## Real-data evidence

Read-only smoke tests ran against three sample archives from a locally
configured GTA VI directory, through the CLI, which shares the decode path with
the desktop. Only aggregate outcomes are recorded here.

- Tiny archive (8.8 KB): 0 recoverable entries, 1 unrecovered region. Handled
  without error; reported as not necessarily empty.
- Mid archive (6.6 MB): 277 entries from 954 streams across 55 regions, of which
  257 were complete XML and 20 were unverified text or binary.
- Mid archive (4.3 MB): 1013 entries, of which 1012 were complete PSO data.
- Export of a complete recovered XML entry wrote exactly the declared decoded
  size and produced valid XML.
- Export of an unverified entry wrote the declared size and printed a caveat
  that the bytes may be whole or partial.
- Overwrite was refused without the overwrite flag and succeeded with it.
- Native metadata on an encrypted archive reported the encryption diagnostic
  (static pass required, cipher type 16, key unavailable) and marked every
  entry unavailable. Native extraction refused the archive and wrote no file.
- A non-existent recovery id produced a clear error and no output file.

## Test coverage

Automated, run this session:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets -- -D warnings`: pass.
- `cargo test --workspace`: 335 tests pass across the binary, core, rage9,
  renderer, CLI and desktop crates, including unit, integration and doc tests.

The export decision logic is covered by unit tests: caveat selection, outcome
messages, the initial save directory, and the single-export rule added in this
branch. The CLI export and metadata paths have integration tests.

Manual, this session: the real-data smoke tests above, plus a code review of the
desktop export flow.

## Known limitations

- The desktop export has no automated GUI test. The pure logic is factored into
  testable functions, but the GPUI wiring, the toast lifecycle and the menu
  gating are verified by code review and by the shared CLI path, not by driving
  the UI. No GUI automation facility was available this session.
- The 3D viewport and renderer demo are out of scope for a recovery Alpha. The
  renderer demo is a debug-only tool.

## User-visible failure behaviour

- A decode or I/O error during export shows a failure toast that stays until
  dismissed and names the reason. No partial final file is written.
- Cancellation removes the toast and writes no file.
- A completed export shows a neutral success toast that clears itself after a
  few seconds. The message never claims recovered bytes are an original file.
- Only one export runs at a time. The Save As actions are disabled while an
  export is running, so a second export cannot displace or silently cancel the
  first.
- Opening an archive shows indexing progress and offers cancellation instead of
  blocking.

## Build reproducibility

- The toolchain is pinned in `rust-toolchain.toml` (1.99.1). GPUI is pinned to a
  Zed git revision, with the matching `async-task` patch mirrored in the root
  `Cargo.toml`.
- CI runs on `windows-2025` and runs fmt, clippy, test and build with
  `--locked`.
- The first build fetches GPUI from GitHub, so a reproducible build needs
  network access on a clean machine.

## Windows x64 packaging requirements

The desktop binary is `leonida-forge.exe`; the CLI is `lforge.exe`.

- Release builds set the Windows subsystem to `windows`, so there is no console.
- Icons are embedded in the binary. The UI font is Segoe UI, a system font, so
  no font is bundled.
- The 3D viewport needs a Direct3D 12 capable GPU. The recovery explorer,
  inspector and export do not.

Open packaging items for a prerelease:

- The MSVC C runtime links dynamically by default, so a clean tester machine
  needs the Visual C++ redistributable. The project SHOULD either document this
  dependency or build with a static CRT.
- The binary has no application icon, version resource or embedded manifest. An
  internal Alpha MAY ship without them; a public release SHOULD add them.

## Remaining release blockers

None block an internal, recovery-focused Alpha.

Before any public release:

- Decide the CRT linkage and ship or document the runtime dependency.
- Add automated coverage, or a documented manual test pass, for the desktop
  export interaction.
- Add a release workflow once these packaging decisions are made.
