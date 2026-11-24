# Builds both release binaries with the static MSVC CRT. Local build paths are
# remapped so the packaged binaries do not reveal the build machine.

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $root

$homeDir = $env:USERPROFILE
if (-not $homeDir) {
    throw 'USERPROFILE is not set'
}
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $homeDir '.cargo' }
$rustupHome = if ($env:RUSTUP_HOME) { $env:RUSTUP_HOME } else { Join-Path $homeDir '.rustup' }

$flags = @(
    '-C'
    'target-feature=+crt-static'
    "--remap-path-prefix=$root=/leonida-forge"
    "--remap-path-prefix=$cargoHome=/cargo"
    "--remap-path-prefix=$rustupHome=/rustup"
)

# Cargo treats these as separate arguments, so paths with spaces stay intact.
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
$env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]0x1F

cargo build --release --locked --target x86_64-pc-windows-msvc -p lforge-desktop -p lforge-cli
if ($LASTEXITCODE -ne 0) {
    throw 'release build failed'
}
