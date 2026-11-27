# Leonida Forge internal Alpha for Linux x64

This is the command-line interface of the recovery-focused Alpha for exploring
GTA VI archives. Unpack the tarball and run `./lforge`. Nothing is installed.
Linux x64 is the only Linux target.

The desktop application remains Windows-only; this archive contains the CLI.

## Contents

- `lforge`: command-line interface.
- `LICENSE.md`: GNU General Public License v3.0 or later.
- `THIRD-PARTY-NOTICES.md`: bundled components and their licenses.

The package contains no game files, no research data and no installer. Every
archive command reads its input; the CLI never writes to an archive. Only the
commands with an `--output` argument write a file, and only to the path given.

## Start

```sh
./lforge --help
./lforge info --json
./lforge archive info game.rpf
./lforge archive recover game.rpf --list
./lforge archive metadata game.rpf --executable game.exe --entries --json
./lforge archive extract game.rpf --executable game.exe --row 42 --output entry.bin
```

The CLI validates publication packages for the website importer:

```sh
./lforge catalog validate catalog-export.zip --json
```

## RPF9 support

RPF9 archives are recognised by their contents, so the extension does not
matter. Archives stored inside other archives are read as well.

Native RPF9 reading is available when the archive's table of contents is stored
without encryption. Leonida Forge then reads native entries with stored bytes,
raw DEFLATE, chunked payloads and companion-file payloads.

Encrypted table-of-contents metadata needs a compatible local executable,
passed with `--executable`. The executable and the archive are read only; the
executable is not copied, and no key state is stored. The metadata signature is
checked before native entries are listed or exported.

Recovered entries are named by archive offset. Their original names and folder
structure are unknown, and the scan does not produce a complete archive
inventory. Recovered and native entries are never mixed in one list.

This is not full native GTA VI RPF9 support.
