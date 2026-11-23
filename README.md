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
Files inside ZIP archives are extracted to a temporary file first, up to 512 MB.

The CLI exposes the same operations on plain files:

```sh
lforge binary info example.bin --json          # size, signature bytes, SHA-256
lforge binary dump example.bin --offset 0x10 --length 128
lforge binary search example.bin --hex "52 50 46 37"
lforge binary search example.bin --text example --json
lforge binary interpret example.bin --offset 0x10 --endian big --json
```

Offsets accept decimal or `0x` hexadecimal. Exit codes: 0 on success, 1 when a command fails, 2 for invalid usage.

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

## Disclaimer

Leonida Forge is an independent, unofficial community project and is not affiliated with or endorsed by Rockstar Games or Take-Two Interactive.

Grand Theft Auto and related trademarks belong to their respective owners.
