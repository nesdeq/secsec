# secsec desktop UIs

A panel app that runs `secsec sync` for one folder: it asks for your SSH-key passphrase at login,
shows the sync's status, and offers **start · stop · restart · open log · settings**. There is one per
platform: a GNOME Shell extension (GNOME 45 to 50) and a macOS menu-bar app.

Both are thin shells around the binary. They read the sync's state with `secsec status <folder>` and
stop a sync with `secsec stop <folder>`, which signals only the process holding that folder's lock
(also one started elsewhere, such as a terminal); starting stops such a sync first, so the UI's own
takes over. Quitting the macOS app or disabling the extension stops only the UI's own child. The
passphrase reaches the child over a pipe, never its command line, and the sync's log lives in the
owner-only `secsec/ui/sync.log` beside `ui.conf`.

## Install

The top-level `install.sh` installs the binary and the UI for your platform, and can link the
folder for you. From a checkout, `./install.sh` in this directory installs only the UI
(`./install.sh --uninstall` removes it).

- **GNOME**: the extension goes to `~/.local/share/gnome-shell/extensions/`. Log out and back in on
  Wayland (Alt+F2, `r` on X11). The sync keeps running while the screen is locked; the panel item is
  hidden there.
- **macOS**: building from a checkout needs the Xcode command-line tools (`xcode-select --install`).
  The app goes to `/Applications` (or `~/Applications`), and the LaunchAgent `com.secsec.ui` starts it
  at every login. After a wake it relaunches the sync from the passphrase it keeps masked in locked
  memory for the session.

## Link the folder once

The UIs only run `secsec sync`; link the folder from a terminal first (or let `install.sh` do it):

```sh
secsec sync ~/cloud --server server.example --pin <host pin> --once             # first device
secsec sync ~/cloud --server server.example --pin <host pin> --invite --once    # joining; prompts for the code
```

`secsec hostpin --serve <dir>` on the server prints the host pin.

## Configure: `secsec/ui.conf`

The file sits in `$XDG_CONFIG_HOME` (else `~/.config`). Set it from the UI (GNOME *Settings*; macOS
*Set sync folder* and *Select SSH key*) or edit it directly (see [`ui.conf.example`](ui.conf.example));
a value runs to the end of its line, so comments go on lines of their own:

```ini
# default ~/cloud; ~ is expanded
folder=~/cloud
# blank uses ~/.ssh/id_ed25519
#key=~/.ssh/id_ed25519
# blank searches the install directories and PATH
#bin=/usr/local/bin/secsec
```

Each UI syncs one folder. A key without a passphrase works too: leave the prompt empty.
