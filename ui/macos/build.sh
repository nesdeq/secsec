#!/bin/sh
# Build the secsec menu-bar app into secsec-menubar.app. Requires the Xcode command-line tools
# (`xcode-select --install`). Run on macOS.
set -eu

cd "$(dirname "$0")"

APP="secsec-menubar.app"
BIN="secsec-menubar"

echo "compiling $BIN…"
swiftc -O "$BIN.swift" -o "$BIN"

echo "bundling $APP…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/$BIN"
cp Info.plist "$APP/Contents/Info.plist"

echo "built $APP"
echo "install:   cp -R $APP /Applications/"
echo "autostart: cp com.secsec.ui.plist ~/Library/LaunchAgents/ && launchctl load -w ~/Library/LaunchAgents/com.secsec.ui.plist"
