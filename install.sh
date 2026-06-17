#!/bin/sh
# secsec installer: fetch the latest release binary for this OS/arch, verify its checksum, install
# it; on Linux also install the systemd --user unit templates. Components are individually selectable.
#
#   curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh        # binary + units
#   curl -fsSL .../install.sh | sh -s -- --binary     # just the binary, no systemd units
#   curl -fsSL .../install.sh | sh -s -- --systemd    # just (re)install the systemd units
#
# Override the binary destination with SECSEC_INSTALL_DIR (default: /usr/local/bin if writable,
# else ~/.local/bin). The desktop menu-bar UIs (GNOME extension / macOS app) are NOT installed here —
# see ui/README.md. Windows: download the .zip from the releases page instead.
set -eu

REPO="nesdeq/secsec"

fail() { echo "error: $1" >&2; exit 1; }

usage() {
    cat <<'EOF'
secsec installer
Usage: install.sh [--binary] [--systemd] [--all] [--help]
  (no flags)  binary + systemd units (Linux) — the default; what the curl|sh one-liner runs
  --binary    install only the secsec binary
  --systemd   install only the systemd --user unit templates (Linux only)
  --all       binary + systemd units (the explicit form of the default)
  -h, --help  show this help
Env: SECSEC_INSTALL_DIR overrides the binary install dir.
The desktop UIs (GNOME extension / macOS menu-bar app) are installed separately — see ui/README.md.
EOF
}

# ---- component selection ----
want_binary=0
want_systemd=0
systemd_required=0   # a literal --systemd makes it an error on a non-Linux / no-systemctl host
explicit=0
while [ $# -gt 0 ]; do
    case "$1" in
        --binary) want_binary=1; explicit=1 ;;
        --systemd) want_systemd=1; systemd_required=1; explicit=1 ;;
        --all) want_binary=1; want_systemd=1; explicit=1 ;;
        -h | --help) usage; exit 0 ;;
        *) fail "unknown option '$1' (try --help)" ;;
    esac
    shift
done
# No flags → the historical default: binary + (best-effort) systemd units.
if [ "$explicit" = 0 ]; then
    want_binary=1
    want_systemd=1
fi

os=$(uname -s)
case "$os" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "unsupported OS '$os' — for Windows, download the .zip from https://github.com/$REPO/releases" ;;
esac

# The binary install dir: SECSEC_INSTALL_DIR, else /usr/local/bin if writable, else ~/.local/bin.
default_install_dir() {
    if [ -n "${SECSEC_INSTALL_DIR:-}" ]; then
        printf '%s\n' "$SECSEC_INSTALL_DIR"
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        printf '%s\n' /usr/local/bin
    else
        printf '%s\n' "$HOME/.local/bin"
    fi
}

# Where an already-installed secsec lives (for unit ExecStart when not installing the binary too).
binary_dir_for_units() {
    p=$(command -v secsec 2>/dev/null || true)
    if [ -n "$p" ]; then
        dirname "$p"
    else
        default_install_dir
    fi
}

INSTALLED_BIN_DIR=""

install_binary() {
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

    dir=$(default_install_dir)
    mkdir -p "$dir" || fail "cannot create $dir"

    # Warn about a different secsec already on PATH — updating $dir/secsec won't remove it, and PATH
    # order could keep the old copy shadowing the new one.
    existing=$(command -v secsec 2>/dev/null || true)
    if [ -n "$existing" ] && [ "$existing" != "$dir/secsec" ]; then
        echo "note: another secsec is installed at $existing — remove it so it can't shadow $dir/secsec"
    fi

    # Stage then atomic-rename, so an update succeeds even while a `secsec sync` is running:
    # overwriting a busy executable in place can fail with ETXTBSY; rename swaps it cleanly (the
    # running process keeps its old inode and picks up the new binary on its next start/restart).
    staged="$dir/.secsec.install.$$"
    install -m 755 secsec "$staged" ||
        fail "cannot write to $dir (try sudo, or set SECSEC_INSTALL_DIR to a writable dir)"
    mv -f "$staged" "$dir/secsec" || { rm -f "$staged"; fail "cannot replace $dir/secsec"; }
    INSTALLED_BIN_DIR="$dir"

    echo "installed: $dir/secsec"
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) echo "note: $dir is not on your PATH — add it to your shell profile" ;;
    esac
}

# systemd user units (Linux). Two templates, installed disabled. The instance is the folder to sync
# (or the store dir to serve), systemd-escaped. An optional per-instance EnvironmentFile carries extra
# flags (e.g. --key, --server on first link, a custom port) via $SECSEC_OPTS; with no such file the
# service just runs `secsec sync|serve <dir>`. serve needs no passphrase; for a headless sync, point
# SECSEC_OPTS at an unencrypted key with --key.
install_systemd() {
    bin_dir="$1"
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$unit_dir"

    cat > "$unit_dir/secsec-sync@.service" <<EOF
[Unit]
Description=secsec continuous two-way sync of %I

[Service]
Type=simple
EnvironmentFile=-%h/.config/secsec/sync@%i.conf
ExecStart=$bin_dir/secsec sync %I \$SECSEC_OPTS
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
ExecStart=$bin_dir/secsec serve %I \$SECSEC_OPTS
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
}

# ---- run the selected components ----
if [ "$want_binary" = 1 ]; then
    install_binary
fi

if [ "$want_systemd" = 1 ]; then
    if [ "$os" != linux ]; then
        [ "$systemd_required" = 0 ] || fail "--systemd is Linux-only"
    elif ! command -v systemctl >/dev/null 2>&1; then
        [ "$systemd_required" = 0 ] || fail "systemctl not found (systemd --user units need it)"
    else
        if [ -n "$INSTALLED_BIN_DIR" ]; then
            bdir="$INSTALLED_BIN_DIR"
        else
            bdir=$(binary_dir_for_units)
            command -v secsec >/dev/null 2>&1 || [ -x "$bdir/secsec" ] ||
                echo "note: secsec not found yet — units will expect it at $bdir/secsec (install with --binary)"
        fi
        install_systemd "$bdir"
    fi
fi
