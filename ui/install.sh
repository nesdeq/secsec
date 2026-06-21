#!/bin/sh
# Install (or uninstall) the secsec desktop UI for the current platform — a thin dispatcher:
#   macOS  → macos/build.sh --install   (compile + copy the .app + load the login LaunchAgent)
#   Linux  → install the GNOME Shell extension (GNOME sessions only)
#
#   ./install.sh             install the UI for this platform
#   ./install.sh --uninstall remove it again
#
# This installs only the UI shell. Install the `secsec` binary with the top-level install.sh, and
# link the folder once by hand first (`secsec sync <folder> --server …`) — see README.md.
set -eu

cd "$(dirname "$0")"

UUID="secsec@nesdeq.github.io"
GNOME_SRC="gnome/$UUID"
GNOME_DEST="${XDG_DATA_HOME:-$HOME/.local/share}/gnome-shell/extensions"

fail() { echo "error: $1" >&2; exit 1; }

usage() {
    cat <<'EOF'
secsec UI installer
Usage: install.sh [--uninstall] [--help]
  (no flags)   install the UI for this platform (macOS menu-bar app / GNOME extension)
  --uninstall  remove it
  -h, --help   show this help
macOS delegates to macos/build.sh; Linux installs the GNOME Shell extension (GNOME only).
The secsec binary and the one-time folder link are separate — see README.md.
EOF
}

# True on a GNOME session: the desktop env names GNOME, or gnome-shell is on PATH.
is_gnome() {
    case "${XDG_CURRENT_DESKTOP:-}" in
        *GNOME*) return 0 ;;
    esac
    command -v gnome-shell >/dev/null 2>&1
}

# How to make gnome-shell pick up the freshly-copied extension, per session type.
reload_hint() {
    case "${XDG_SESSION_TYPE:-}" in
        wayland) echo "log out and back in" ;;
        x11)     echo "press Alt+F2, type 'r', Enter" ;;
        *)       echo "reload GNOME Shell (re-login)" ;;
    esac
}

gnome_install() {
    is_gnome || fail "not a GNOME session (XDG_CURRENT_DESKTOP=${XDG_CURRENT_DESKTOP:-unset}) — the Linux UI is a GNOME Shell extension; install by hand for other desktops (see README.md)"

    echo "installing GNOME extension → $GNOME_DEST/$UUID …"
    mkdir -p "$GNOME_DEST"
    rm -rf "${GNOME_DEST:?}/$UUID"
    cp -R "$GNOME_SRC" "$GNOME_DEST/"

    # Best-effort enable now; it takes once the shell has reloaded and seen the new files.
    if command -v gnome-extensions >/dev/null 2>&1; then
        gnome-extensions enable "$UUID" 2>/dev/null || true
    fi

    echo "installed — $(reload_hint), then: gnome-extensions enable $UUID"
}

gnome_uninstall() {
    if command -v gnome-extensions >/dev/null 2>&1; then
        gnome-extensions disable "$UUID" 2>/dev/null || true
    fi
    echo "removing $GNOME_DEST/$UUID …"
    rm -rf "${GNOME_DEST:?}/$UUID"
    echo "uninstalled — $(reload_hint) to drop it from the panel."
}

os=$(uname -s)
case "${1:-}" in
    "" | --install)
        case "$os" in
            Darwin) exec sh macos/build.sh --install ;;
            Linux)  gnome_install ;;
            *) fail "unsupported OS '$os' — Windows has no menu-bar UI; see README.md" ;;
        esac
        ;;
    --uninstall)
        case "$os" in
            Darwin) exec sh macos/build.sh --uninstall ;;
            Linux)  gnome_uninstall ;;
            *) fail "unsupported OS '$os'" ;;
        esac
        ;;
    -h | --help)
        usage
        ;;
    *)
        fail "unknown option '$1' (try --help)"
        ;;
esac
