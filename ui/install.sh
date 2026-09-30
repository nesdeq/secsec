#!/bin/sh
# Install (default) or --uninstall the desktop UI from this checkout: the macOS menu-bar app or the GNOME Shell extension.
set -eu

cd "$(dirname "$0")"

UUID="secsec@nesdeq.github.io"
GNOME_DEST="${XDG_DATA_HOME:-$HOME/.local/share}/gnome-shell/extensions"

fail() { echo "error: $1" >&2; exit 1; }

usage() {
    echo "usage: ./install.sh [--uninstall]"
    echo "  macOS: builds and installs the menu-bar app and its login agent (macos/build.sh)"
    echo "  Linux: installs the GNOME Shell extension for this user"
    echo "The secsec binary comes from the repository's top-level install.sh."
}

is_gnome() {
    case "${XDG_CURRENT_DESKTOP:-}" in
        *GNOME*) return 0 ;;
    esac
    command -v gnome-shell >/dev/null 2>&1
}

# How gnome-shell picks up new extension code in this session type.
reload_hint() {
    case "${XDG_SESSION_TYPE:-}" in
        x11) echo "press Alt+F2, type r, Enter" ;;
        *) echo "log out and back in" ;;
    esac
}

gnome_install() {
    is_gnome || fail "not a GNOME session (XDG_CURRENT_DESKTOP=${XDG_CURRENT_DESKTOP:-unset}); the Linux UI is a GNOME Shell extension"
    mkdir -p "$GNOME_DEST"
    rm -rf "${GNOME_DEST:?}/$UUID"
    cp -R "gnome/$UUID" "$GNOME_DEST/"
    if command -v gnome-extensions >/dev/null 2>&1; then
        gnome-extensions enable "$UUID" 2>/dev/null || true
    fi
    echo "installed $GNOME_DEST/$UUID: $(reload_hint), then check that it is enabled (gnome-extensions enable $UUID)"
}

gnome_uninstall() {
    if command -v gnome-extensions >/dev/null 2>&1; then
        gnome-extensions disable "$UUID" 2>/dev/null || true
    fi
    rm -rf "${GNOME_DEST:?}/$UUID"
    echo "uninstalled: $(reload_hint) to drop it from the panel"
}

os=$(uname -s)
case "${1:-}" in
    "" | --install)
        case "$os" in
            Darwin) exec sh macos/build.sh --install ;;
            Linux) gnome_install ;;
            *) fail "no desktop UI for $os" ;;
        esac
        ;;
    --uninstall)
        case "$os" in
            Darwin) exec sh macos/build.sh --uninstall ;;
            Linux) gnome_uninstall ;;
            *) fail "no desktop UI for $os" ;;
        esac
        ;;
    -h | --help) usage ;;
    *) fail "unknown option '$1' (try --help)" ;;
esac
