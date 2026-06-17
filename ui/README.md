# secsec — desktop menu-bar UIs

Thin native shells around the `secsec` binary, one per platform. Each one:

- **At login**, pops a native password dialog, then spawns
  `secsec sync <folder> --passphrase-stdin [--key <keyfile>]` and writes the passphrase to the
  child's **stdin** — so the secret travels over a pipe and never appears on the command line
  (invisible to `ps`/`top`/`/proc`).
- Redirects the sync process's stdout+stderr to `~/.config/secsec/ui/sync.log`.
- Shows a **retro LED** in the menu bar as the connect status, refreshed every 15 s from process
  liveness + the log: ● green = connected, ● amber = connecting/reconnecting, ● red = problem
  (error/alarm in the log), ○ grey = stopped.
- Menu: **status** (+ last log line) · **start/stop** · **restart** · **open log** · **settings**
  (folder + SSH key).

They **spawn the binary directly** (not via systemd/launchd) — see *Relation to systemd* below. All
the crypto, sync, and history logic stays in the single `secsec` binary; "open log" shows the live sync
output (`sync: UpToDate`, `watching…`, merge conflicts, the P7 rollback alarm), not `secsec log`.

## Prerequisite: link the folder once, by hand

The UIs only run `secsec sync`; they don't do first-time setup. Link the folder once from a terminal
(this is also where you verify the host fingerprint out-of-band, and pair via `--invite`):

```sh
secsec sync ~/cloud --server server.example          # first device, or:
secsec sync ~/cloud --server server.example --invite CODE
```

After that first link, the UI drives `secsec sync ~/cloud` on its own.

## Config — `~/.config/secsec/ui.conf`

Shared by both UIs, and **editable from within the UI** (no need to touch the file): GNOME has a
*Settings…* preferences window with native folder/key pickers; macOS has *Set sync folder…* and
*Select SSH key…* menu items. The file (see [`ui.conf.example`](ui.conf.example)):

```ini
folder=~/cloud                 # default ~/cloud; ~ is expanded
#key=~/.ssh/id_ed25519         # optional — blank uses the default key
#bin=/usr/local/bin/secsec     # optional — default searches the install dirs + PATH
```

> Your SSH key must have a passphrase for the prompt to make sense. An *empty*-passphrase key needs
> no prompt — in that case use a plain `systemctl --user`/launchd job instead of these UIs.

## GNOME (Shell extension)

`gnome/secsec@nesdeq.github.io/` — a GJS extension for GNOME Shell **45–50**. It loads at gnome-shell
start, so "start at login" is free.

```sh
cp -R gnome/secsec@nesdeq.github.io ~/.local/share/gnome-shell/extensions/
# log out and back in (Wayland), or Alt+F2 → `r` (X11), then:
gnome-extensions enable secsec@nesdeq.github.io
```

It prompts ~1.2 s after enable. Cancel to skip auto-start; use the menu's **Start sync** later. Open
**Settings (folder · SSH key)…** from the menu (or `gnome-extensions prefs secsec@nesdeq.github.io`)
to set the folder and key with native pickers — changes apply on the next Start/Restart.

## macOS (menu-bar agent)

`macos/secsec-menubar.swift` — a single-file `NSStatusItem` agent. Build with the Xcode command-line
tools:

```sh
cd macos
./build.sh                              # → secsec-menubar.app
cp -R secsec-menubar.app /Applications/
cp com.secsec.ui.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.secsec.ui.plist   # start at login
```

Runs as an accessory (menu-bar only, no Dock icon). Use *Set sync folder…* / *Select SSH key…* for
native pickers. Edit the path in `com.secsec.ui.plist` if you install the `.app` elsewhere.

## Relation to systemd / launchd

These UIs are for the **encrypted-key + prompt-at-login** case. The headless service path is
different and complementary:

- The `secsec sync@`/`secsec serve@` **systemd user units** (installed by `install.sh` on Linux) run
  `secsec sync <dir>` with **no stdin and no TTY**, so they cannot type a passphrase. A systemd job
  therefore needs an **empty-passphrase key** (or, advanced: pipe a secret in via systemd encrypted
  credentials — out of scope here). `--passphrase-stdin` is for *interactive launchers* (these UIs,
  or any parent that writes the child's stdin), not for the units.
- Run **either** a UI **or** a unit for a given folder, not both (they'd both spawn `secsec sync`).
- macOS: the `com.secsec.ui.plist` LaunchAgent starts this app at login; it *is* the launchd
  integration (it prompts, unlike a bare service).

## Install

The one-line `install.sh` installs the **binary** and the Linux systemd units (`--binary` /
`--systemd` / `--all` select components). It does **not** install these UIs — install them by hand
per the steps above (copy the GNOME extension / build the macOS app).

## Notes & limits

- **One folder.** Both UIs sync a single folder (the one in `ui.conf`). Multiple folders → use extra
  `systemctl --user`/LaunchAgent jobs (empty-passphrase keys) instead.
- **Log is truncated per launch.** Each start replaces `sync.log`; it's an operational tail.
- **Passphrase lifetime.** It lives only long enough to write to the child's stdin, then is dropped;
  the binary zeroizes it after decrypting and `mlock`s the derived key. Cancelling the prompt just
  doesn't start the sync.
