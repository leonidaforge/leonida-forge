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

The RPF9 table of contents is encrypted, and Leonida Forge does not read it.
It scans the archive data for zlib streams and lists what it finds instead.
The first visit reads the whole archive. A 773 MB archive takes about 2 seconds from the disk cache.
The index goes to `%APPDATA%\Leonida Forge\cache\rpf` and is reused until the archive's size or modification time changes.

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
