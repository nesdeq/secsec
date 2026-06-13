#!/bin/sh
# secsec installer: fetch the latest release binary for this OS/arch, verify its checksum,
# install it. Usage:  curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh
# Override the destination with SECSEC_INSTALL_DIR (default: /usr/local/bin if writable,
# else ~/.local/bin). Windows: download the .zip from the releases page instead.
set -eu

REPO="nesdeq/secsec"

fail() { echo "error: $1" >&2; exit 1; }

os=$(uname -s)
case "$os" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "unsupported OS '$os' — for Windows, download the .zip from https://github.com/$REPO/releases" ;;
esac

arch=$(uname -m)
case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "unsupported architecture '$arch' (releases cover x86_64 and aarch64)" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

# Resolve the latest release tag from the /releases/latest redirect (no API token, no jq).
effective=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
    fail "cannot reach github.com"
tag=${effective##*/}
{ [ -n "$tag" ] && [ "$tag" != "latest" ]; } || fail "no published release found"

archive="secsec-$tag-$os-$arch.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "secsec $tag ($os-$arch): downloading…"
curl -fsSL -o "$tmp/$archive" "$base/$archive" || fail "download failed: $base/$archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

cd "$tmp"
line=$(grep "[[:space:]]$archive\$" SHA256SUMS) || fail "$archive not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    echo "$line" | sha256sum -c - >/dev/null || fail "checksum mismatch for $archive"
else
    echo "$line" | shasum -a 256 -c - >/dev/null || fail "checksum mismatch for $archive"
fi

tar -xzf "$archive"
[ -f secsec ] || fail "archive did not contain the secsec binary"

dir="${SECSEC_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
    if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        dir=/usr/local/bin
    else
        dir="$HOME/.local/bin"
    fi
fi
mkdir -p "$dir"
install -m 755 secsec "$dir/secsec"

echo "installed: $dir/secsec"
case ":$PATH:" in
    *":$dir:"*) ;;
    *) echo "note: $dir is not on your PATH — add it to your shell profile" ;;
esac

# systemd user units (Linux). Two templates, installed disabled. The instance is the folder to sync
# (or the store dir to serve), systemd-escaped. An optional per-instance EnvironmentFile carries
# extra flags (e.g. --key, --server on first link, a custom port) via $SECSEC_OPTS; with no such file
# the service just runs `secsec sync|serve <dir>`. serve needs no passphrase; for a headless sync,
# point SECSEC_OPTS at an unencrypted key with --key.
if [ "$os" = linux ] && [ -n "${HOME:-}" ] && command -v systemctl >/dev/null 2>&1; then
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$unit_dir"

    cat > "$unit_dir/secsec-sync@.service" <<EOF
[Unit]
Description=secsec continuous two-way sync of %I

[Service]
Type=simple
EnvironmentFile=-%h/.config/secsec/sync@%i.conf
ExecStart=$dir/secsec sync %I \$SECSEC_OPTS
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
EOF

    cat > "$unit_dir/secsec-serve@.service" <<EOF
[Unit]
Description=secsec blind sync server, store %I

[Service]
Type=simple
EnvironmentFile=-%h/.config/secsec/serve@%i.conf
ExecStart=$dir/secsec serve %I \$SECSEC_OPTS
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload >/dev/null 2>&1 || true
    echo "systemd user units installed in $unit_dir:"
    echo "  client (folder already linked):"
    echo "    systemctl --user enable --now secsec-sync@\$(systemd-escape -p ~/Sync).service"
    echo "  server:"
    echo "    systemctl --user enable --now secsec-serve@\$(systemd-escape -p /srv/data).service"
    echo "  extra flags: set SECSEC_OPTS=... in ~/.config/secsec/{sync,serve}@<escaped>.conf"
    echo "  start without an active login (boot/headless): sudo loginctl enable-linger $(id -un)"
fi
