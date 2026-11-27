#!/usr/bin/env bash
# Packages the Linux x64 Alpha archive from an already built release executable.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

bin_dir=${BIN_DIR:-$root/target/x86_64-unknown-linux-gnu/release}
output_dir=${OUTPUT_DIR:-$root/dist}
cli=$bin_dir/lforge

fail() {
    printf 'package: %s\n' "$1" >&2
    exit 1
}

[ -f "$cli" ] || fail "missing executable: $cli"
[ -x "$cli" ] || fail "$cli is not executable"
file "$cli" | grep -q 'ELF 64-bit' || fail "$cli is not an x64 ELF executable"

metadata=$(cargo metadata --locked --format-version 1)
version=${VERSION:-$(printf '%s' "$metadata" | jq -r '.packages[] | select(.name == "lforge-cli") | .version' | head -n 1)}
[ -n "$version" ] || fail 'cannot read the lforge-cli version'

help=$("$cli" --help)
grep -q 'Usage: lforge' <<<"$help" || fail 'lforge --help printed no usage text'

info=$("$cli" info --json)
jq -e --arg version "$version" \
    '.version == $version and .os == "linux" and .arch == "x86_64" and .profile == "release"' \
    <<<"$info" >/dev/null || fail "lforge info reports unexpected build information: $info"

check_local_path() {
    local path=$1
    local escaped
    escaped=$(printf '%s' "$path" | sed 's#[][\\.^$*+?(){}|]#\\&#g')
    if strings -a "$cli" | grep -qE "(^|[^[:alnum:]_])${escaped}"; then
        fail "lforge embeds the local path $path"
    fi
}

for prefix in "$root/" "${CARGO_HOME:-$HOME/.cargo}/" "${RUSTUP_HOME:-$HOME/.rustup}/"; do
    [ -n "$prefix" ] || continue
    check_local_path "$prefix"
done

tree=$(cargo tree --locked --target x86_64-unknown-linux-gnu --edges normal --prefix none -p lforge-cli)
component_ids=$(printf '%s\n' "$tree" |
    sed -n 's/^\([^ ]*\) v\([^ ]*\).*/\1 \2/p' |
    sort -u |
    jq -R . |
    jq -s .)
notices=$(printf '%s' "$metadata" | jq -r --argjson ids "$component_ids" '
    "# Third-party components",
    "",
    "Leonida Forge is licensed under GPL-3.0-or-later. It includes the",
    "third-party components below in its Linux x64 release build. Each",
    "entry records the license declared by the package metadata; the full",
    "text is in that package'"'"'s source.",
    "",
    (.packages
        | map(select(.source != null) as $package
            | select($ids | index($package.name + " " + $package.version))
            | $package)
        | sort_by(.name, .version)
        | .[]
        | "- `\(.name) \(.version)`, " + (
            if .license then .license
            elif .license_file then "see " + .license_file
            else "license not declared"
            end)
        + (
            if .repository then ", " + .repository
            elif (.source // "") | startswith("git+") then
                ", " + (.source | ltrimstr("git+") | split("?")[0] | split("#")[0])
            else "" end))')

name="leonida-forge-$version-linux-x64"
stage=$output_dir/$name
rm -rf -- "$stage"
mkdir -p -- "$stage"
install -m 0755 "$cli" "$stage/lforge"
install -m 0644 "$root/LICENSE.md" "$stage/LICENSE.md"
install -m 0644 "$root/packaging/linux-README.md" "$stage/README.md"
printf '%s\n' "$notices" >"$stage/THIRD-PARTY-NOTICES.md"

tarball=$output_dir/$name.tar.gz
rm -f -- "$tarball" "$tarball.sha256"
tar -C "$output_dir" -czf "$tarball" "$name"
hash=$(sha256sum "$tarball" | cut -d' ' -f1)
printf '%s  %s\n' "$hash" "$name.tar.gz" >"$tarball.sha256"

printf 'Created %s\n' "$tarball"
printf 'Created %s\n' "$tarball.sha256"
printf 'SHA-256: %s\n' "$hash"
