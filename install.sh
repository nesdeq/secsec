#!/bin/sh
# secsec installer: the binary and desktop UI (default), --server for the blind server as a user service, --binary for the binary alone.
set -eu

REPO="nesdeq/secsec"
UUID="secsec@nesdeq.github.io"
DEFAULT_PORT=8899

fail() { printf 'error: %s\n' "$1" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

usage() {
    cat <<'EOF'
secsec installer

  curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh                  # client
  curl -fsSL https://raw.githubusercontent.com/nesdeq/secsec/main/install.sh | sh -s -- --server   # server

Modes (re-running a mode updates it in place):
  (default)          the secsec binary, the desktop UI (GNOME extension or macOS menu-bar app),
                     and an optional guided link of a folder to a server
  --server           the binary and the blind server as a user service (systemd --user with lingering
                     on Linux, a LaunchAgent on macOS), its data directory, port, and authorized keys
  --binary           only the secsec binary

Options:
  --version TAG      install this release instead of the latest
  --no-ui            client mode without the desktop UI (Linux: offers a systemd sync service instead)
  --folder DIR       client: the folder to link and sync
  --link HOST[:PORT] client: the server to link the folder to
  --pin HEX          client: the server's host pin (`secsec hostpin --serve <dir>` on the server)
  --invite           client: join an existing repository (secsec prompts for the invite code)
  --dir DIR          server: data directory for the repository and host key
  --port PORT        server: UDP port (default 8899)
  --authorize KEY    server: add a device public key line (ssh-ed25519 ...) to authorized_keys; repeatable
  -y, --yes          never prompt: take flags and defaults
  -h, --help         this help

Questions are asked on the terminal (/dev/tty), also under `curl | sh`; without a terminal, or with
--yes, flags and defaults are used. SECSEC_INSTALL_DIR overrides the binary directory (default:
/usr/local/bin when writable, else ~/.local/bin); SECSEC_RELEASE_URL points at a mirror of the release
assets (with --version). Windows: download the .zip from the releases page.
EOF
}

# ---- arguments ----

mode=client
want_ui=1
assume_yes=0
tag=""
folder=""
link=""
pin=""
invite=0
srv_dir=""
port=""
authorize=""
need_arg() { [ $# -ge 2 ] || fail "$1 needs a value"; }
while [ $# -gt 0 ]; do
    case "$1" in
        --server) mode=server ;;
        --binary) mode=binary ;;
        --no-ui) want_ui=0 ;;
        -y | --yes) assume_yes=1 ;;
        --version) need_arg "$@"; tag=$2; shift ;;
        --folder) need_arg "$@"; folder=$2; shift ;;
        --link) need_arg "$@"; link=$2; shift ;;
        --pin) need_arg "$@"; pin=$2; shift ;;
        --invite) invite=1 ;;
        --dir) need_arg "$@"; srv_dir=$2; shift ;;
        --port) need_arg "$@"; port=$2; shift ;;
        --authorize) need_arg "$@"; authorize="$authorize$2
" ; shift ;;
        -h | --help) usage; exit 0 ;;
        *) fail "unknown option '$1' (try --help)" ;;
    esac
    shift
done

# ---- terminal questions ----

if [ "$assume_yes" = 0 ] && (: < /dev/tty) 2>/dev/null; then interactive=1; else interactive=0; fi

# ask VAR QUESTION DEFAULT: read an answer from the terminal, or take DEFAULT without one.
ask() {
    ans=$3
    if [ "$interactive" = 1 ]; then
        if [ -n "$3" ]; then printf '%s [%s]: ' "$2" "$3" > /dev/tty; else printf '%s: ' "$2" > /dev/tty; fi
        IFS= read -r ans < /dev/tty || ans=""
        [ -n "$ans" ] || ans=$3
    fi
    eval "$1=\$ans"
}

# confirm QUESTION DEFAULT(y|n): yes or no, the default without a terminal.
confirm() {
    ans=$2
    if [ "$interactive" = 1 ]; then
        if [ "$2" = y ]; then printf '%s [Y/n] ' "$1" > /dev/tty; else printf '%s [y/N] ' "$1" > /dev/tty; fi
        IFS= read -r ans < /dev/tty || ans=""
        [ -n "$ans" ] || ans=$2
    fi
    case "$ans" in y | Y | yes | Yes | YES) return 0 ;; *) return 1 ;; esac
}

# ---- platform ----

os=$(uname -s)
case "$os" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) fail "unsupported OS '$os'; for Windows download the .zip from https://github.com/$REPO/releases" ;;
esac
arch=$(uname -m)
case "$arch" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) fail "unsupported architecture '$arch' (releases cover x86_64 and aarch64)" ;;
esac
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

config_root() {
    case "${XDG_CONFIG_HOME:-}" in
        /*) printf '%s/secsec\n' "$XDG_CONFIG_HOME" ;;
        *) printf '%s/.config/secsec\n' "$HOME" ;;
    esac
}
CONF=$(config_root)

# ---- downloads ----

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ -n "${SECSEC_RELEASE_URL:-}" ]; then
    [ -n "$tag" ] || fail "SECSEC_RELEASE_URL needs --version"
    fetch() { curl -fsSL -o "$1" "$2"; }
    base="${SECSEC_RELEASE_URL%/}"
else
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$1" "$2"; }
    if [ -z "$tag" ]; then
        effective=$(curl -fsSLI --proto '=https' -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
            fail "cannot reach github.com"
        tag=${effective##*/}
        { [ -n "$tag" ] && [ "$tag" != latest ]; } || fail "no published release found"
    fi
    base="https://github.com/$REPO/releases/download/$tag"
fi
fetch "$tmp/SHA256SUMS" "$base/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then provenance=1; else provenance=0; fi
[ "$provenance" = 1 ] || say "note: the GitHub CLI (gh) is not signed in, so only SHA-256 checksums are verified, not build provenance"

# download NAME: fetch a release asset into $tmp and verify its checksum (and provenance with gh).
download() {
    fetch "$tmp/$1" "$base/$1" || fail "download failed: $base/$1"
    line=$(grep "[[:space:]]$1\$" "$tmp/SHA256SUMS") || fail "$1 is not listed in SHA256SUMS"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null) || fail "checksum mismatch for $1"
    else
        (cd "$tmp" && printf '%s\n' "$line" | shasum -a 256 -c - >/dev/null) || fail "checksum mismatch for $1"
    fi
    if [ "$provenance" = 1 ]; then
        gh attestation verify "$tmp/$1" --repo "$REPO" >/dev/null 2>&1 || fail "build provenance check failed for $1"
    fi
}

# ---- binary ----

install_dir() {
    if [ -n "${SECSEC_INSTALL_DIR:-}" ]; then
        printf '%s\n' "$SECSEC_INSTALL_DIR"
    elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
        printf '%s\n' /usr/local/bin
    else
        printf '%s\n' "$HOME/.local/bin"
    fi
}

BIN=""
install_binary() {
    archive="secsec-$tag-$os-$arch.tar.gz"
    say "secsec $tag ($os-$arch): downloading"
    download "$archive"
    mkdir -p "$tmp/bin"
    tar -xzf "$tmp/$archive" -C "$tmp/bin"
    [ -f "$tmp/bin/secsec" ] || fail "$archive does not contain the secsec binary"
    dir=$(install_dir)
    mkdir -p "$dir" || fail "cannot create $dir"
    before=""
    [ -x "$dir/secsec" ] && before=$("$dir/secsec" --version 2>/dev/null || true)
    # A rename swaps the file even while a sync runs from it; the running process keeps the old inode until it restarts.
    staged="$dir/.secsec.install.$$"
    install -m 755 "$tmp/bin/secsec" "$staged" || fail "cannot write to $dir (use sudo, or set SECSEC_INSTALL_DIR)"
    mv -f "$staged" "$dir/secsec" || { rm -f "$staged"; fail "cannot replace $dir/secsec"; }
    BIN="$dir/secsec"
    after=$("$BIN" --version)
    if [ -n "$before" ] && [ "$before" != "$after" ]; then say "updated $BIN: $before -> $after"; else say "installed $BIN ($after)"; fi
    other=$(command -v secsec 2>/dev/null || true)
    if [ -n "$other" ] && [ "$other" != "$BIN" ]; then say "note: $other shadows $BIN on your PATH; remove one of them"; fi
    case ":$PATH:" in
        *":$dir:"*) ;;
        *) say "note: $dir is not on your PATH; add it to your shell profile" ;;
    esac
}

# ---- desktop UI ----

# conf_set KEY VALUE: set one ui.conf key, keeping the others; the file stays owner-only.
conf_set() {
    mkdir -p "$CONF"
    chmod 700 "$CONF"
    f="$CONF/ui.conf"
    t="$f.install.$$"
    if [ -f "$f" ]; then grep -v "^[[:space:]]*$1[[:space:]]*=" "$f" > "$t" || true; else printf '# secsec desktop UI config (managed by the secsec UI)\n' > "$t"; fi
    printf '%s=%s\n' "$1" "$2" >> "$t"
    chmod 600 "$t"
    mv -f "$t" "$f"
}

# conf_get KEY: a ui.conf value, empty when unset.
conf_get() {
    [ -f "$CONF/ui.conf" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONF/ui.conf" | tail -n 1
}

is_gnome() {
    case "${XDG_CURRENT_DESKTOP:-}" in *GNOME*) return 0 ;; esac
    command -v gnome-shell >/dev/null 2>&1
}

# Add the extension to org.gnome.shell enabled-extensions, so it loads at the next login.
gnome_enable() {
    command -v gsettings >/dev/null 2>&1 || return 0
    list=$(gsettings get org.gnome.shell enabled-extensions 2>/dev/null) || return 0
    case "$list" in *"'$UUID'"*) return 0 ;; esac
    case "$list" in
        "@as []" | "[]") list="['$UUID']" ;;
        *) list="${list%]}, '$UUID']" ;;
    esac
    gsettings set org.gnome.shell enabled-extensions "$list" 2>/dev/null || true
    if [ "$(gsettings get org.gnome.shell disable-user-extensions 2>/dev/null || echo false)" = true ]; then
        say "note: user extensions are disabled in GNOME; enable them in the Extensions app"
    fi
}

install_gnome_ui() {
    dest="${XDG_DATA_HOME:-$HOME/.local/share}/gnome-shell/extensions"
    asset="secsec-ui-gnome-$tag.tar.gz"
    download "$asset"
    mkdir -p "$dest" "$tmp/ui"
    tar -xzf "$tmp/$asset" -C "$tmp/ui"
    [ -f "$tmp/ui/$UUID/metadata.json" ] || fail "$asset does not contain the extension"
    updating=0
    [ -d "$dest/$UUID" ] && updating=1
    rm -rf "${dest:?}/$UUID"
    cp -R "$tmp/ui/$UUID" "$dest/"
    gnome_enable
    if [ "$updating" = 1 ]; then
        say "updated the GNOME extension; it loads the new version at your next login (use Restart sync to pick up the new binary now)"
    else
        say "installed the GNOME extension; it starts at your next login"
    fi
}

install_macos_ui() {
    asset="secsec-ui-macos-$tag.tar.gz"
    download "$asset"
    mkdir -p "$tmp/ui"
    tar -xzf "$tmp/$asset" -C "$tmp/ui"
    [ -d "$tmp/ui/secsec-menubar.app" ] || fail "$asset does not contain secsec-menubar.app"
    if [ -w /Applications ]; then apps=/Applications; else apps="$HOME/Applications"; fi
    mkdir -p "$apps"
    rm -rf "${apps:?}/secsec-menubar.app"
    cp -R "$tmp/ui/secsec-menubar.app" "$apps/"
    label=com.secsec.ui
    plist="$HOME/Library/LaunchAgents/$label.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$plist.install" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$apps/secsec-menubar.app/Contents/MacOS/secsec-menubar</string>
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
    mv -f "$plist.install" "$plist"
    say "installed $apps/secsec-menubar.app; it starts at every login"
    if confirm "Start the menu-bar app now (it asks for your SSH key passphrase)?" y; then
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "$plist" || say "note: could not start it now; it starts at your next login"
    fi
}

# ---- folder link ----

LINKED=""
link_folder() {
    if [ -z "$link" ]; then
        [ "$interactive" = 1 ] || return 0
        confirm "Link a folder to a secsec server now?" y || return 0
    fi
    current=$(conf_get folder)
    ask folder "Folder to keep in sync" "${folder:-${current:-$HOME/cloud}}"
    case $folder in \~) folder=$HOME ;; \~/*) folder="$HOME/${folder#\~/}" ;; esac
    ask link "Server (host or host:port)" "$link"
    [ -n "$link" ] || { say "no server given; link later with: secsec sync $folder --server <host> --pin <host pin>"; return 0; }
    ask pin "Server host pin (from 'secsec hostpin --serve <dir>' on the server; blank trusts the first connection)" "$pin"
    if [ "$invite" = 0 ] && confirm "Join an existing repository with an invite code from an enrolled device?" n; then invite=1; fi
    set -- sync "$folder" --server "$link" --once
    [ -n "$pin" ] && set -- "$@" --pin "$pin"
    [ "$invite" = 1 ] && set -- "$@" --invite
    say "linking $folder to $link"
    if [ "$interactive" = 1 ]; then "$BIN" "$@" < /dev/tty; else "$BIN" "$@"; fi || {
        say "the link did not complete; fix the cause above and run: secsec $*"
        return 0
    }
    LINKED=$folder
    conf_set folder "$folder"
}

# A systemd user service that keeps a linked folder in sync without a desktop session.
install_sync_service() {
    command -v systemctl >/dev/null 2>&1 || return 0
    unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$unit_dir"
    cat > "$unit_dir/secsec-sync@.service.install" <<EOF
[Unit]
Description=secsec two-way sync of %I

[Service]
Type=simple
EnvironmentFile=-%E/secsec/sync@%i.conf
ExecStart="$(sd_escape "$BIN")" sync "%I" \$SECSEC_OPTS
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
EOF
    mv -f "$unit_dir/secsec-sync@.service.install" "$unit_dir/secsec-sync@.service"
    systemctl --user daemon-reload 2>/dev/null || true
    say "installed the systemd user unit secsec-sync@.service"
    [ -n "$LINKED" ] || { say "  enable it for a linked folder: systemctl --user enable --now secsec-sync@\$(systemd-escape -p <folder>).service"; return 0; }
    instance=$(systemd-escape --path "$LINKED")
    say "  a service cannot type a passphrase: it needs a key without one, set in $CONF/sync@$instance.conf as SECSEC_OPTS=--key <file>"
    if confirm "Run the sync of $LINKED as a service now and at every boot?" n; then
        systemctl --user enable --now "secsec-sync@$instance.service"
        ensure_linger
    fi
}

# ---- server ----

# A path made safe for a systemd unit line: % doubled.
sd_escape() { printf '%s' "$1" | sed 's/%/%%/g'; }

ensure_linger() {
    [ "$os" = linux ] || return 0
    user=$(id -un)
    if [ "$(loginctl show-user "$user" --property=Linger --value 2>/dev/null || true)" = yes ]; then return 0; fi
    if loginctl enable-linger "$user" 2>/dev/null; then say "enabled lingering: your user services run from boot, without a login"; return 0; fi
    if command -v sudo >/dev/null 2>&1 && confirm "Enable lingering with sudo, so the service runs from boot without a login?" y; then
        # sudo asks for its password on the terminal itself; without one it must not prompt at all.
        if [ "$interactive" = 1 ]; then sudo loginctl enable-linger "$user"; else sudo -n loginctl enable-linger "$user"; fi &&
            { say "enabled lingering for $user"; return 0; }
    fi
    say "note: lingering is off, so the service stops when you log out; enable it with: sudo loginctl enable-linger $user"
}

SERVER_ENV="$CONF/server.env"

setup_authorized_keys() {
    ak="$HOME/.ssh/authorized_keys"
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    [ -f "$ak" ] || : > "$ak"
    chmod 600 "$ak"
    printf '%s' "$authorize" | while IFS= read -r k; do
        [ -n "$k" ] || continue
        case "$k" in ssh-ed25519\ *) ;; *) fail "--authorize takes an ssh-ed25519 public key line" ;; esac
        grep -qxF "$k" "$ak" || printf '%s\n' "$k" >> "$ak"
    done
    if [ "$interactive" = 1 ]; then
        say "secsec serve admits only device keys in $ak. That file also grants SSH logins to this account,"
        say "so run the server as a dedicated user if those devices should not be able to log in here."
        while :; do
            ask key "Paste a device public key (the ssh-ed25519 line of its ~/.ssh/id_ed25519.pub; blank to finish)" ""
            [ -n "$key" ] || break
            case "$key" in
                ssh-ed25519\ *) grep -qxF "$key" "$ak" || printf '%s\n' "$key" >> "$ak"; say "  added" ;;
                *) say "  not an ssh-ed25519 key line; skipped" ;;
            esac
        done
    fi
    count=$(grep -c '^ssh-ed25519 ' "$ak" || true)
    [ "$count" -gt 0 ] || say "warning: $ak holds no ssh-ed25519 keys, and secsec serve refuses to start without one; add a device's key, then restart the service"
}

install_server() {
    old_dir=""
    old_port=""
    if [ -f "$SERVER_ENV" ]; then
        old_dir=$(sed -n 's/^SECSEC_SERVE_DIR=//p' "$SERVER_ENV")
        old_port=$(sed -n 's/^SECSEC_SERVE_PORT=//p' "$SERVER_ENV")
    fi
    ask srv_dir "Server data directory" "${srv_dir:-${old_dir:-${XDG_DATA_HOME:-$HOME/.local/share}/secsec/server}}"
    case $srv_dir in \~/*) srv_dir="$HOME/${srv_dir#\~/}" ;; esac
    case "$srv_dir" in /*) ;; *) srv_dir="$(pwd)/$srv_dir" ;; esac
    ask port "UDP port" "${port:-${old_port:-$DEFAULT_PORT}}"
    case "$port" in '' | *[!0-9]*) fail "the port must be a number" ;; esac
    { [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; } || fail "the port must be between 1 and 65535"
    mkdir -p "$srv_dir"
    chmod 700 "$srv_dir"
    setup_authorized_keys
    host_pin=$("$BIN" hostpin --serve "$srv_dir")
    mkdir -p "$CONF"
    chmod 700 "$CONF"
    printf 'SECSEC_SERVE_DIR=%s\nSECSEC_SERVE_PORT=%s\n' "$srv_dir" "$port" > "$SERVER_ENV.install"
    mv -f "$SERVER_ENV.install" "$SERVER_ENV"

    if [ "$os" = linux ]; then
        command -v systemctl >/dev/null 2>&1 || fail "systemctl not found: the server runs as a systemd user service"
        unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
        mkdir -p "$unit_dir"
        cat > "$unit_dir/secsec-serve.service.install" <<EOF
[Unit]
Description=secsec blind sync server ($(sd_escape "$srv_dir"))
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="$(sd_escape "$BIN")" serve "$(sd_escape "$srv_dir")" --port $port
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
EOF
        mv -f "$unit_dir/secsec-serve.service.install" "$unit_dir/secsec-serve.service"
        systemctl --user daemon-reload
        systemctl --user enable secsec-serve.service >/dev/null
        systemctl --user restart secsec-serve.service
        ensure_linger
        if systemctl --user is-active --quiet secsec-serve.service; then
            say "secsec-serve is running (journalctl --user -u secsec-serve for its log)"
        else
            say "warning: secsec-serve did not stay up; see: journalctl --user -u secsec-serve"
        fi
    else
        label=com.secsec.serve
        plist="$HOME/Library/LaunchAgents/$label.plist"
        mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
        cat > "$plist.install" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$BIN</string>
		<string>serve</string>
		<string>$srv_dir</string>
		<string>--port</string>
		<string>$port</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$HOME/Library/Logs/secsec-serve.log</string>
	<key>StandardErrorPath</key>
	<string>$HOME/Library/Logs/secsec-serve.log</string>
</dict>
</plist>
EOF
        mv -f "$plist.install" "$plist"
        launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
        launchctl bootstrap "gui/$(id -u)" "$plist"
        say "secsec serve runs as a LaunchAgent while you are logged in (log: ~/Library/Logs/secsec-serve.log)"
    fi
    say ""
    say "open udp/$port in your firewall, then on each device:"
    say "  secsec sync <folder> --server <this host>:$port --pin $host_pin"
    say "host pin: $host_pin"
}

# ---- run ----

install_binary
case "$mode" in
    binary) ;;
    server) install_server ;;
    client)
        if [ "$want_ui" = 1 ]; then
            if [ "$os" = macos ]; then
                install_macos_ui
            elif is_gnome; then
                install_gnome_ui
            else
                say "no desktop UI for this session (the Linux UI is a GNOME Shell extension)"
                want_ui=0
            fi
        fi
        conf_set bin "$BIN"
        link_folder
        if [ "$want_ui" = 0 ] && [ "$os" = linux ]; then install_sync_service; fi
        ;;
esac
