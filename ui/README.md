# secsec — desktop menu-bar UIs

A menu-bar / panel app that runs `secsec sync` for one folder: it prompts for your SSH-key passphrase
at login, shows connect status, and gives you **start · stop · restart · open log · settings** from the
menu. One per platform — a GNOME Shell extension and a macOS menu-bar agent.

## Link the folder once, first

The UIs only run `secsec sync` — do the one-time setup from a terminal (this is also where you verify
the host fingerprint and pair a new device):

```sh
secsec sync ~/cloud --server server.example          # first device, or:
secsec sync ~/cloud --server server.example --invite CODE
```

## Install

Run `./install.sh` from this directory — it installs for your platform; `./install.sh --uninstall`
removes it. (The `secsec` binary itself is installed separately by the repo-root `install.sh`.)

### GNOME (Shell extension, GNOME 45–50)

```sh
./install.sh                 # copies the extension + enables it
# then log out and back in (Wayland), or Alt+F2 → `r` (X11)
```

Re-run after any change to the extension. It prompts ~1.2 s after enable; cancel to skip and use
**Start sync** from the menu later.

### macOS (menu-bar agent)

```sh
./install.sh                 # builds, copies to /Applications, loads the login agent
```

Needs the Xcode command-line tools (`xcode-select --install`). Runs menu-bar-only, no Dock icon.

## Configure — `~/.config/secsec/ui.conf`

Set it from the UI (GNOME *Settings…*; macOS *Set sync folder…* / *Select SSH key…*) or edit the file
directly (see [`ui.conf.example`](ui.conf.example)):

```ini
folder=~/cloud                 # default ~/cloud; ~ is expanded
#key=~/.ssh/id_ed25519         # optional — blank uses the default key
#bin=/usr/local/bin/secsec     # optional — default searches the install dirs + PATH
```

Your SSH key must have a passphrase, and each UI syncs a single folder.
