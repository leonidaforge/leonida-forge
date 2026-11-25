# Leonida Forge

**Open-source GTA VI research and modding toolkit.**

Leonida Forge is a community-driven project dedicated to researching GTA VI's file formats and scripting systems, and building tools to explore, analyze, and eventually modify them.

The project aims to provide a native desktop application and CLI featuring archive exploration, script decompilation, native function research, asset conversion, and future Blender integration.

Our goal is to make GTA VI modding more accessible through open research, shared knowledge, and reliable tooling.

## Building

Leonida Forge currently builds on Windows 11 x64 only.

Requirements:

- [rustup](https://rustup.rs). `rust-toolchain.toml` pins the toolchain, and rustup installs it on first use.
- Visual Studio Build Tools with the "Desktop development with C++" workload and a Windows SDK. GPUI needs the SDK's resource compiler.
- A GPU with Direct3D 12 support for the 3D viewport.

The first build fetches GPUI from the Zed repository, which takes a few minutes.

```sh
cargo run -p lforge-desktop    # desktop application
cargo run -p lforge-cli -- info --json
cargo test --workspace
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
```

Offsets accept decimal or `0x` hexadecimal. Exit codes: 0 on success, 1 when a command fails, 2 for invalid usage.

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

- `Recovered Entries` has one folder per detected kind, such as `XML`, `PSO` or `Resources`.
  Files are named after their archive offset, for example `0x000000B000.xml`. Original names and folders are unknown.
- `Resource Pages` has one file per page of each reconstructed resource.
- `Unrecovered Regions` holds bytes that are not zlib streams, shown as stored.

An entry is complete when it starts with a known file signature and ends with a chunk shorter than 64 KiB.
Entries without a known signature are unverified and may be parts of larger files.

A RAGE resource is stored as one zlib stream per page, system pages first.
Leonida Forge reads the page counts from the resource's page map and takes the pages from the streams that follow.
A resource file holds its system pages, then its graphics pages.
A resource is complete when every declared page is there and the page sizes fit the pattern seen in GTA VI data.
It is partial when pages are missing, and unverified when its page map fails validation.
These rules come from observed data, not from game code.

```sh
lforge archive info data.rpf --json            # header fields and a recovery summary
lforge archive list data.rpf --json            # entries, resource pages and unrecovered regions
lforge archive resource data.rpf 0x2010 --json # pages and checks of one resource
```

`--no-cache` neither reads nor writes the index cache.

`lforge archive recover` exports one recovered entry at a time, for archives whose native table of contents cannot be decrypted.

```sh
lforge archive recover data.rpf --list --json             # the recovery candidates
lforge archive recover data.rpf --id 0x0000000080 --output file.bin
```

A candidate is one recovered entry, identified by the archive offset of its first stream. The scan produces the same offset again for unchanged data, so the id is stable across scans. `--list` reports each candidate's observed properties, the offset, byte range, zlib compression, compressed and decoded sizes, and whether the bytes start with a known file signature, apart from its inferred ones, the content kind and the completeness status. Candidates are not native entries. They have no original names or paths, and the list is not a complete archive inventory.

`recover --id ID --output FILE` re-decodes one candidate and writes its bytes with the same output safety as `archive extract`. The streams are checked against the index as they are read, the output goes through a temporary file and replaces an existing file only with `--overwrite`, and a failed decode leaves no partial file. A partial or unverified candidate is written with a note that bytes may be missing. A decode that succeeds is not proof that the bytes are an authentic original file.

Where the table of contents is stored without encryption, it can be read directly instead of scanned. With a compatible local game executable, `--executable` authenticates a processed table of contents first.

```sh
lforge archive metadata data.rpf --entries --executable game.exe   # the native entries and how each one reads
lforge archive extract data.rpf --row 42 --output file.bin --executable game.exe
```

Entries are identified by their row number in the table. `archive metadata --entries` lists them and reports, for each one, whether its contents are readable as stored, readable after supported decoding, or unavailable. When an entry is unavailable it gives the reason: an unsupported payload transform, an unsupported compression mode, a companion file that is missing or invalid, or malformed metadata. It also reports whether the table was authenticated by a signature check or read without one because the archive needs no processing pass.

`archive extract` writes one entry to `--output`, decoded where its storage is supported. It handles stored bytes, raw DEFLATE, and chunked payloads whose chunks are zlib streams or copied, including entries whose bytes live in a companion file next to the archive. It refuses encrypted or processed metadata, payload transforms and compression modes it cannot decode, and companions that are not available, rather than writing wrong bytes. The output goes through a temporary file in the destination directory and replaces an existing file only with `--overwrite`; a failed decode leaves no partial file behind.

RPF9 stores a hash of each entry's path, not the path. `archive metadata --entries` always shows the stored hash and key. A local name table can add candidate names, but a name is display data: it never changes a row's key, a payload offset, an authentication result or an extraction destination. `--name-file FILE` reads one; without it, `<archive>.names.txt` next to the archive is used when present. The table is UTF-8, one entry per line: a candidate path, or `hash64:HASH<TAB>NAME` and `key32:HASH<TAB>NAME` for a declared key. Candidate paths are verified by hashing them with the type's class. A declared name is verified only when its normalized form or its stem reproduces the key; otherwise it is reported as unconfirmed. Use `--archive-path`, `--mount-prefix` and `--extension` to describe paths that the built-in `rpf` mapping cannot.

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

## License

Leonida Forge is licensed under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`). See [LICENSE.md](LICENSE.md).

## Disclaimer

Leonida Forge is an independent, unofficial community project and is not affiliated with or endorsed by Rockstar Games or Take-Two Interactive.

Grand Theft Auto and related trademarks belong to their respective owners.
