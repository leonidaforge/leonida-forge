# Builds the Windows x64 Alpha archive from already built release binaries.
# The release build itself sets RUSTFLAGS="-C target-feature=+crt-static".

[CmdletBinding()]
param(
    [string]$BinDir,
    [string]$OutputDir,
    [string]$Version
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $root

if (-not $BinDir) {
    $BinDir = Join-Path $root 'target\x86_64-pc-windows-msvc\release'
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $root 'dist'
}
$BinDir = (Resolve-Path -LiteralPath $BinDir).Path

$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata failed'
}
if (-not $Version) {
    $Version = ($metadata.packages |
        Where-Object { $_.name -eq 'lforge-desktop' } |
        Select-Object -First 1).version
}

$desktop = Join-Path $BinDir 'leonida-forge.exe'
$cli = Join-Path $BinDir 'lforge.exe'

function Read-AsciiZ {
    param([byte[]]$Bytes, [int]$Offset)
    $end = $Offset
    while ($end -lt $Bytes.Length -and $Bytes[$end] -ne 0) {
        $end++
    }
    [Text.Encoding]::ASCII.GetString($Bytes, $Offset, $end - $Offset)
}

function Convert-RvaToOffset {
    param(
        [byte[]]$Bytes,
        [int]$SectionTable,
        [int]$SectionCount,
        [uint32]$Rva
    )
    for ($i = 0; $i -lt $SectionCount; $i++) {
        $section = $SectionTable + 40 * $i
        $virtualSize = [BitConverter]::ToUInt32($Bytes, $section + 8)
        $virtualAddress = [BitConverter]::ToUInt32($Bytes, $section + 12)
        $rawSize = [BitConverter]::ToUInt32($Bytes, $section + 16)
        $rawOffset = [BitConverter]::ToUInt32($Bytes, $section + 20)
        $span = [Math]::Max($virtualSize, $rawSize)
        if ($Rva -ge $virtualAddress -and $Rva -lt ($virtualAddress + $span)) {
            return [int]($Rva - $virtualAddress + $rawOffset)
        }
    }
    throw ('RVA 0x{0:X} is not mapped by a section' -f $Rva)
}

function Get-PeImage {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "missing executable: $Path"
    }
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x40) {
        throw "$Path is too small to be a PE image"
    }
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($pe -lt 0 -or $pe + 24 -ge $bytes.Length) {
        throw "$Path has no PE header"
    }
    if ($bytes[$pe] -ne 0x50 -or $bytes[$pe + 1] -ne 0x45 -or
        $bytes[$pe + 2] -ne 0 -or $bytes[$pe + 3] -ne 0) {
        throw "$Path is not a PE image"
    }

    $coff = $pe + 4
    $machine = [BitConverter]::ToUInt16($bytes, $coff)
    $sectionCount = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $optional = $coff + 20
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    if ($magic -ne 0x20B) {
        throw "$Path is not a 64-bit PE image"
    }
    $subsystem = [BitConverter]::ToUInt16($bytes, $optional + 68)
    $directoryCount = [BitConverter]::ToUInt32($bytes, $optional + 108)
    $sectionTable = $optional + $optionalSize

    $imports = @()
    if ($directoryCount -gt 1) {
        $importRva = [BitConverter]::ToUInt32($bytes, $optional + 112 + 8)
        if ($importRva -ne 0) {
            $position = Convert-RvaToOffset $bytes $sectionTable $sectionCount $importRva
            while ($position + 20 -le $bytes.Length) {
                $nameRva = [BitConverter]::ToUInt32($bytes, $position + 12)
                $firstThunk = [BitConverter]::ToUInt32($bytes, $position + 16)
                if ($nameRva -eq 0 -and $firstThunk -eq 0) {
                    break
                }
                if ($nameRva -eq 0) {
                    throw "$Path has a malformed import descriptor"
                }
                $nameOffset = Convert-RvaToOffset $bytes $sectionTable $sectionCount $nameRva
                $imports += Read-AsciiZ $bytes $nameOffset
                $position += 20
            }
        }
    }

    [pscustomobject]@{
        Path = $Path
        Machine = $machine
        Subsystem = $subsystem
        Imports = $imports
    }
}

function Get-ThirdPartyNotices {
    param($Components)
    $lines = @(
        '# Third-party components'
        ''
        'Leonida Forge is licensed under GPL-3.0-or-later. It includes the'
        'third-party components below in its Windows x64 release build. Each'
        'entry records the license declared by the package metadata; the full'
        'text is in that package''s source.'
        ''
    )
    foreach ($package in $Components) {
        $license = if ($package.license) {
            $package.license
        } elseif ($package.license_file) {
            "see $($package.license_file)"
        } else {
            'license not declared'
        }
        $repository = if ($package.repository) {
            $package.repository
        } elseif ($package.source -match '^git\+(.+?)(\?|#|$)') {
            $Matches[1]
        } else {
            ''
        }
        $line = "- ``$($package.name) $($package.version)``, $license"
        if ($repository) {
            $line += ", $repository"
        }
        $lines += $line
    }
    ($lines -join "`n") + "`n"
}

$desktopPe = Get-PeImage $desktop
$cliPe = Get-PeImage $cli

foreach ($image in @($desktopPe, $cliPe)) {
    if ($image.Machine -ne 0x8664) {
        throw "$($image.Path) is not an x64 executable"
    }
    $crtImports = $image.Imports | Where-Object {
        $_ -match '^(VCRUNTIME|MSVCP|api-ms-win-crt-)'
    }
    if ($crtImports) {
        throw "$($image.Path) still imports the dynamic CRT: $($crtImports -join ', ')"
    }
}
if ($desktopPe.Subsystem -ne 2) {
    throw 'leonida-forge.exe does not use the Windows GUI subsystem'
}
if ($cliPe.Subsystem -ne 3) {
    throw 'lforge.exe does not use the Windows console subsystem'
}

$help = & $cli --help 2>&1
if ($LASTEXITCODE -ne 0) {
    throw 'lforge.exe --help failed'
}
if (($help -join "`n") -notmatch 'Usage: lforge') {
    throw 'lforge.exe --help printed no usage text'
}
$info = (& $cli info --json) -join "`n" | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'lforge.exe info --json failed'
}
if ($info.version -ne $Version -or $info.arch -ne 'x86_64') {
    throw "lforge.exe reports unexpected build information: $info"
}

$name = "leonida-forge-$Version-windows-x64"
$stage = Join-Path $OutputDir $name
if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item -LiteralPath $desktop, $cli, (Join-Path $root 'LICENSE.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'packaging\README.md') -Destination (Join-Path $stage 'README.md')
$tree = cargo tree --locked --target x86_64-pc-windows-msvc --edges normal --prefix none -p lforge-desktop -p lforge-cli
if ($LASTEXITCODE -ne 0) {
    throw 'cargo tree failed'
}
$componentIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($line in $tree) {
    if ($line -match '^(\S+) v(\S+?)(?:\s+\(|$)') {
        [void]$componentIds.Add("$($Matches[1]) $($Matches[2])")
    }
}
$byId = @{}
foreach ($package in $metadata.packages) {
    $byId["$($package.name) $($package.version)"] = $package
}
$components = $componentIds |
    Sort-Object |
    ForEach-Object { $byId[$_] } |
    Where-Object { $_.source }
$notices = Get-ThirdPartyNotices $components
[IO.File]::WriteAllText(
    (Join-Path $stage 'THIRD-PARTY-NOTICES.md'),
    $notices,
    [Text.UTF8Encoding]::new($false)
)

$zip = Join-Path $OutputDir "$name.zip"
if (Test-Path -LiteralPath $zip) {
    Remove-Item -LiteralPath $zip -Force
}
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal

$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
$checksum = "$zip.sha256"
[IO.File]::WriteAllText(
    $checksum,
    "$hash  $name.zip`n",
    [Text.UTF8Encoding]::new($false)
)

Write-Host "Created $zip"
Write-Host "Created $checksum"
Write-Host "SHA-256: $hash"
