# Internal Alpha readiness

Scope: the Windows desktop explorer, its export workflow and the Windows x64
package for an internal, recovery-focused Alpha. Date: 2026-11-24.

## Verdict

A recovery-focused internal Alpha is ready to hand to testers as an install-free
ZIP. The scan-recovery, inspect and export pipeline works in automated tests and
against the real archives recorded below. The packaged desktop binary starts on
this Windows 11 machine and its window responds.

Full native encrypted RPF9 support is not ready and remains under research. The
table-of-contents decryption key is not available, so the tools refuse encrypted
native metadata instead of guessing. That is correct behaviour.

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

Automated, run for this package:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass.
- `cargo test --workspace --locked`: 338 tests pass across the binary, core,
  rage9, renderer, CLI and desktop crates, including unit, integration and doc
  tests.
- `cargo build --workspace --locked`: pass.
- Release build for `x86_64-pc-windows-msvc`: pass.

The export slot is covered by focused unit tests: overlapping dialog requests,
a cancelled dialog whose result arrives late, and a delayed dialog completing
while an export runs. The tests assert that a losing request never writes its
destination and never takes the slot from a running export.

The CLI export and metadata paths have integration tests. The desktop export
file writer has tests for success, overwrite, cancellation, a missing companion
and a failed finalisation.

Manual, for this package: the packaged desktop launched on this Windows 11
machine, showed a responsive `Leonida Forge` window, and was stopped by the
test harness. No GUI interaction was performed.

## Known limitations

- The desktop export flow has no automated GUI test. The slot decisions are
  unit tested, but the GPUI wiring, the save dialog, the toast lifecycle and
  the menu gating need a manual pass.
- The 3D viewport and renderer demo are out of scope for a recovery Alpha. The
  renderer demo is a debug-only tool.
- A recovered entry can be partial or unverified. The status is shown, and an
  export keeps the caveat, but the bytes are not proof of an original file.

## User-visible failure behaviour

- A decode or I/O error during export shows a failure toast that stays until
  dismissed and names the reason. No partial final file is written.
- Cancellation removes the toast and writes no file.
- A completed export shows a neutral success toast that clears itself after a
  few seconds. The message never claims recovered bytes are an original file.
- Only one export request is active at a time. A save dialog holds the slot, so
  a second request is refused while the dialog is open or an export is running.
- Opening an archive shows indexing progress and offers cancellation instead of
  blocking.

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

Both binaries use the static MSVC CRT. The release build sets:

```powershell
$env:RUSTFLAGS = "-C target-feature=+crt-static"
```

This is the Rust-supported `crt-static` target feature. The repository does not
set it globally, so development, clippy and test builds keep the default
dynamic CRT and match CI.

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
$env:RUSTFLAGS = "-C target-feature=+crt-static"
cargo build --release --locked --target x86_64-pc-windows-msvc -p lforge-desktop -p lforge-cli
pwsh -NoProfile -File scripts/package-windows-x64.ps1
```

The first build fetches GPUI from the pinned Zed revision, so a clean machine
needs network access. The package script verifies both executables, their PE
machine and subsystem, the absence of dynamic CRT imports, and that the CLI
answers `--help` and reports the expected version. It then stages only the
listed files, writes the ZIP and prints the SHA-256.

## GitHub Actions workflow

`.github/workflows/windows-alpha.yml` is manual (`workflow_dispatch`) and uses
`windows-2025`. It checks out the selected commit, installs the pinned
toolchain, then runs the CI gates: fmt, clippy, tests and the locked workspace
build. It then builds the two release binaries with static CRT linking, runs
the packaging script, and uploads only `dist/*.zip` and `dist/*.sha256` with
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
6. Open an encrypted retail RPF9 archive. Confirm indexing progress appears,
   recovery grouping and status are shown, and the limitation is explained.
7. Browse `Recovered Entries`, `Resource Pages` and `Unrecovered Regions`.
   Confirm offsets, sizes and completeness text are plausible.
8. Open a plain file and an entry inside an archive in the Binary Inspector.
   Check the signature, size and search.
9. Export through the entry context menu, then through **File > Save Selection
   As**. Confirm the suggested name, destination folder and result toast.
10. Save to an existing file. Confirm the save dialog asks before replacing it,
    and that cancelling the overwrite leaves the old file unchanged.
11. Cancel an export while it runs. Confirm no new or partial file is left.
12. Start a second export while the first save dialog is open, then while the
    first export is running. Confirm Save As is disabled in both cases, that
    cancelling the dialog re-enables it, and that finishing or failing the
    export re-enables it again.
13. Run `lforge.exe --help`, `lforge.exe info`, and `lforge.exe archive info`
    on an RPF9 archive.
14. Run `lforge.exe archive recover <archive> --list`, then export one
    candidate. Confirm overwrite protection and the unverified-bytes note.
15. Check that `%APPDATA%\Leonida Forge` holds settings and the archive index,
    and that no game file changed.

Record which steps ran, the Windows build, the GPU and any archive samples used.
Do not put game files in the package or the repository.

## Remaining blockers

For the internal Alpha, none. The package is ready to hand to testers.

Still required before a public prerelease:

- Complete the clean-machine checklist above, including the desktop interactions
  that have no automated test.
- Decide the supported RPF9 claim. Native encrypted metadata remains unreadable,
  so public text must keep the recovery scope.
- Add an application icon, version resource and manifest if the desktop is
  published outside the internal group.
- Complete a third-party license-text audit for every bundled component.
- Add a tag-triggered prerelease workflow only after publication is approved.
