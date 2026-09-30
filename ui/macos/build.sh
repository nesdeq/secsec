#!/bin/sh
# Build (default), --install, or --uninstall the secsec menu-bar app; needs the Xcode command-line tools.
set -eu

cd "$(dirname "$0")"

APP="secsec-menubar.app"
BIN="secsec-menubar"
LABEL="com.secsec.ui"
AGENT_PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

# A universal (arm64 + x86_64) app bundle, matching LSMinimumSystemVersion in Info.plist.
build() {
    echo "compiling $BIN (arm64, x86_64)"
    swiftc -O -target arm64-apple-macos11 "$BIN.swift" -o "$BIN-arm64"
    swiftc -O -target x86_64-apple-macos11 "$BIN.swift" -o "$BIN-x86_64"
    lipo -create -output "$BIN" "$BIN-arm64" "$BIN-x86_64"
    rm -f "$BIN-arm64" "$BIN-x86_64"
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
    cp "$BIN" "$APP/Contents/MacOS/$BIN"
    cp Info.plist "$APP/Contents/Info.plist"
    cp secsec.icns "$APP/Contents/Resources/secsec.icns"
    echo "built $APP"
}

# /Applications when writable, else ~/Applications.
apps_dir() {
    if [ -w /Applications ]; then echo /Applications; else echo "$HOME/Applications"; fi
}

# The login agent that starts the app at every login (RunAtLoad).
write_agent() {
    mkdir -p "$(dirname "$AGENT_PLIST")"
    cat > "$AGENT_PLIST.tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>$1/$APP/Contents/MacOS/$BIN</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
EOF
    mv -f "$AGENT_PLIST.tmp" "$AGENT_PLIST"
}

agent_reload() {
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$AGENT_PLIST"
}

install_app() {
    dir=$(apps_dir)
    mkdir -p "$dir"
    echo "installing $dir/$APP"
    rm -rf "${dir:?}/$APP"
    cp -R "$APP" "$dir/"
    write_agent "$dir"
    agent_reload
    echo "installed: the menu-bar app is running and starts at every login"
}

uninstall_app() {
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$AGENT_PLIST"
    for dir in /Applications "$HOME/Applications"; do
        rm -rf "${dir:?}/$APP"
    done
    echo "uninstalled"
}

case "${1:-}" in
    --install) build; install_app ;;
    --uninstall) uninstall_app ;;
    "") build ;;
    -h | --help) echo "usage: ./build.sh [--install | --uninstall]" ;;
    *) echo "unknown option: $1 (usage: ./build.sh [--install | --uninstall])" >&2; exit 1 ;;
esac
