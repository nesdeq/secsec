#!/bin/sh
# Build, install, or uninstall the secsec menu-bar app. Requires the Xcode command-line tools
# (`xcode-select --install`). Run on macOS.
#
#   ./build.sh              build secsec-menubar.app (default)
#   ./build.sh --install    build, copy to /Applications, (re)load the login LaunchAgent
#   ./build.sh --uninstall  unload the LaunchAgent, remove the app + plist
set -eu

cd "$(dirname "$0")"

APP="secsec-menubar.app"
BIN="secsec-menubar"
PLIST="com.secsec.ui.plist"
APPS_DIR="/Applications"
AGENTS_DIR="$HOME/Library/LaunchAgents"
AGENT_PLIST="$AGENTS_DIR/$PLIST"

build() {
    echo "compiling ${BIN}…"
    swiftc -O "$BIN.swift" -o "$BIN"

    echo "bundling ${APP}…"
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS"
    cp "$BIN" "$APP/Contents/MacOS/$BIN"
    cp Info.plist "$APP/Contents/Info.plist"
    mkdir -p "$APP/Contents/Resources"
    cp secsec.icns "$APP/Contents/Resources/secsec.icns"

    echo "built $APP"
}

install_app() {
    echo "installing ${APPS_DIR}/${APP}…"
    rm -rf "${APPS_DIR:?}/$APP"
    cp -R "$APP" "$APPS_DIR/"

    echo "installing ${AGENT_PLIST}…"
    mkdir -p "$AGENTS_DIR"
    cp "$PLIST" "$AGENT_PLIST"

    # Unload any prior instance, then load -w: starts secsec now and at every login (RunAtLoad).
    echo "reloading launchctl…"
    launchctl unload "$AGENT_PLIST" 2>/dev/null || true
    launchctl load -w "$AGENT_PLIST"

    echo "installed — secsec is running and will start at login"
}

uninstall_app() {
    if [ -f "$AGENT_PLIST" ]; then
        echo "unloading + removing ${AGENT_PLIST}…"
        launchctl unload -w "$AGENT_PLIST" 2>/dev/null || true
        rm -f "$AGENT_PLIST"
    fi

    echo "removing ${APPS_DIR}/${APP}…"
    rm -rf "${APPS_DIR:?}/$APP"

    echo "uninstalled"
}

case "${1:-}" in
    --install)
        build
        install_app
        ;;
    --uninstall)
        uninstall_app
        ;;
    -h|--help)
        echo "usage: ./build.sh [--install | --uninstall]"
        echo "  (no args)    build $APP only"
        echo "  --install    build, copy to $APPS_DIR, (re)load the login LaunchAgent"
        echo "  --uninstall  unload the LaunchAgent, remove the app + plist"
        ;;
    "")
        build
        echo "install:   ./build.sh --install     (copy to $APPS_DIR + load LaunchAgent)"
        echo "uninstall: ./build.sh --uninstall   (remove app + LaunchAgent)"
        ;;
    *)
        echo "unknown option: $1" >&2
        echo "usage: ./build.sh [--install | --uninstall]" >&2
        exit 1
        ;;
esac
