# Leonida Forge internal Alpha for Windows x64

This is a recovery-focused Alpha for exploring GTA VI archives. Unpack the ZIP
and run either executable. Nothing is installed. Windows 11 x64 is the only
supported target.

## Contents

- `leonida-forge.exe`: desktop explorer.
- `lforge.exe`: command-line interface.
- `LICENSE.md`: GNU General Public License v3.0 or later.
- `THIRD-PARTY-NOTICES.md`: bundled components and their licenses.

The package contains no game files, no research data and no installer. The
desktop app writes settings and its archive index under
`%APPDATA%\Leonida Forge`. It opens game files read-only.

## Start

Double-click `leonida-forge.exe`. The explorer opens the last folder you used,
or the configured GTA VI folder. Use **File > Set GTA VI Folder** or **File >
Open Folder** to choose one.

For the CLI:

```sh
lforge --help
lforge info
lforge archive info game.rpf
lforge archive recover game.rpf --list
```

## RPF9 support

The explorer opens RPF9 and ZIP archives like folders. Archives are recognised
by their contents, so the extension does not matter. Archives stored inside
other archives open as well, up to eight levels deep.

Native RPF9 reading is available when the archive's table of contents is stored
without encryption. Leonida Forge then reads native entries with stored bytes,
raw DEFLATE, chunked payloads and companion-file payloads.

The table of contents in retail game archives is encrypted, and this build does
not decrypt it. For those archives the explorer scans the data for zlib streams
and lists recovery candidates instead. Recovered entries are named by archive
offset. Their original names and folder structure are unknown, and the scan
does not produce a complete archive inventory.

This is not full native GTA VI RPF9 support.

## Features

- Browse folders, ZIP archives and RPF9 archives as one tree.
- Recover entries from encrypted RPF9 archives and group them by detected kind.
- Reconstruct RAGE resources from consecutive page streams.
- Inspect any file as bytes in the Binary Inspector.
- Export an entry from its context menu or from **File > Save Selection As**.
- List and export recovery candidates from the CLI.

## Known limitations

- Encrypted RPF9 table-of-contents metadata is not decrypted.
- Recovered entries have no original names or paths.
- A recovered entry can be partial or unverified. The UI reports its status,
  and an export keeps that caveat in the result message.
- Payload transforms and compression modes beyond the supported list are
  refused rather than guessed.
- All file access is read-only.
- One export runs at a time. The save dialog takes the slot before it opens,
  so a second request is refused until the first finishes or is cancelled.
- Files read from an archive are capped at 512 MB. The 3D viewport needs a
  Direct3D 12 capable GPU; the explorer and export do not.

## Export safety

Export writes to a temporary file in the destination folder and moves it into
place only after the whole payload decodes. A failed or cancelled export leaves
no partial final file. An existing file is replaced only after you confirm it
in the save dialog. A successful export does not prove the bytes are an
authentic original file.

## Verification

This Alpha requires no Visual C++ Redistributable. Both executables use the
static MSVC runtime and import only Windows system DLLs.

## License and disclaimer

Leonida Forge is free software under the GNU General Public License v3.0 or
later. See `LICENSE.md`.

Leonida Forge is an independent, unofficial community project. It is not
affiliated with or endorsed by Rockstar Games or Take-Two Interactive. Grand
Theft Auto and related trademarks belong to their respective owners.
