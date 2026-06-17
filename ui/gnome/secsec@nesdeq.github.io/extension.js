// secsec — GNOME Shell extension (GNOME 45+ ESM).
//
// A thin shell around the `secsec` binary: at login it prompts for the SSH-key passphrase, spawns
// `secsec sync <folder> --passphrase-stdin [--key <keyfile>]`, and feeds the passphrase over the
// child's stdin pipe — so the secret never appears in argv (invisible to `ps`/`top`). The child's
// stdout+stderr are redirected to ~/.config/secsec/ui/sync.log; the panel menu shows status,
// tails that log, and opens Settings (folder + SSH key) in the preferences window.
//
// Config: ~/.config/secsec/ui.conf — `folder=<path>` (default ~/cloud), optional `key=<ssh key>`,
// optional `bin=<path to secsec>`. The folder must already be linked by a manual first
// `secsec sync <folder> --server …`. `~` is expanded in `folder` and `key`.

import GObject from 'gi://GObject';
import St from 'gi://St';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {ModalDialog} from 'resource:///org/gnome/shell/ui/modalDialog.js';

const PROMPT_DELAY_MS = 1200; // let the session settle before popping the login prompt

// Expand a leading `~` / `~/` to the home dir (config paths may be typed with a tilde).
function expandPath(p) {
    if (!p)
        return p;
    if (p === '~')
        return GLib.get_home_dir();
    if (p.startsWith('~/'))
        return GLib.build_filenamev([GLib.get_home_dir(), p.slice(2)]);
    return p;
}

function defaultFolder() {
    return GLib.build_filenamev([GLib.get_home_dir(), 'cloud']);
}

// Parse ~/.config/secsec/ui.conf — simple `key=value` lines; `#` comments and blanks ignored.
// `folder` defaults to ~/cloud; `key` empty means the default ~/.ssh/id_ed25519.
function readConfig() {
    const path = GLib.build_filenamev([GLib.get_user_config_dir(), 'secsec', 'ui.conf']);
    const cfg = {folder: '', bin: 'secsec', key: ''};
    let bytes;
    try {
        [, bytes] = GLib.file_get_contents(path);
    } catch (_) {
        bytes = null;
    }
    if (bytes) {
        for (let line of new TextDecoder().decode(bytes).split('\n')) {
            line = line.trim();
            if (!line || line.startsWith('#'))
                continue;
            const eq = line.indexOf('=');
            if (eq < 0)
                continue;
            const key = line.slice(0, eq).trim();
            const val = line.slice(eq + 1).trim();
            if (key === 'folder')
                cfg.folder = val;
            else if (key === 'key')
                cfg.key = val;
            else if (key === 'bin' && val)
                cfg.bin = val;
        }
    }
    if (!cfg.folder)
        cfg.folder = defaultFolder();
    return cfg;
}

function logPath() {
    // Kept under ~/.config/secsec/ alongside ui.conf so the UI's files don't scatter.
    const dir = GLib.build_filenamev([GLib.get_user_config_dir(), 'secsec', 'ui']);
    GLib.mkdir_with_parents(dir, 0o755);
    return GLib.build_filenamev([dir, 'sync.log']);
}

// Last non-empty line of the log, or '' if none — used for the inline status.
function lastLogLine(path) {
    let bytes;
    try {
        [, bytes] = GLib.file_get_contents(path);
    } catch (_) {
        return '';
    }
    const lines = new TextDecoder().decode(bytes).split('\n').filter(l => l.trim());
    return lines.length ? lines[lines.length - 1] : '';
}

// Retro LED look per status: filled dot when running (green/amber/red), hollow when stopped.
const LED = {
    connected: {glyph: '●', color: '#33ff66'},
    connecting: {glyph: '●', color: '#ffcc33'},
    error: {glyph: '●', color: '#ff3b30'},
    stopped: {glyph: '○', color: '#9aa0a6'},
};

// Health from process liveness + the log tail (the 15 s poll). Scans the log newest-first: a hard
// error marker → 'error', a transient "connection lost" → 'connecting', a healthy sync line →
// 'connected'; a running process with nothing notable is assumed 'connected'.
function healthFromLog(path, running) {
    if (!running)
        return 'stopped';
    let bytes;
    try {
        [, bytes] = GLib.file_get_contents(path);
    } catch (_) {
        return 'connected';
    }
    const lines = new TextDecoder().decode(bytes).split('\n').map(l => l.trim().toLowerCase());
    const HARD = ['reconnect failed', 'sync error', 'alarm', 'wrong passphrase', 'could not', 'no server'];
    const WARN = ['connection lost'];
    const OK = ['watching', 'sync: uptodate', 'sync: pushed', 'sync: pulled', 'sync: merged',
        'sync: published', 'sync: cloned', 'synced '];
    for (let i = lines.length - 1; i >= 0; i--) {
        const l = lines[i];
        if (!l)
            continue;
        if (HARD.some(m => l.includes(m)))
            return 'error';
        if (WARN.some(m => l.includes(m)))
            return 'connecting';
        if (OK.some(m => l.includes(m)))
            return 'connected';
    }
    return 'connected';
}

// A native modal asking for the key passphrase (masked). Calls onSubmit(passphrase) on Unlock,
// onCancel() on Cancel/Escape.
const PassphraseDialog = GObject.registerClass(
class PassphraseDialog extends ModalDialog {
    _init(folder, onSubmit, onCancel) {
        super._init({styleClass: 'prompt-dialog'});
        this._onSubmit = onSubmit;
        this._onCancel = onCancel;
        this._done = false;

        const box = new St.BoxLayout({vertical: true, style_class: 'message-dialog-content'});
        this.contentLayout.add_child(box);
        box.add_child(new St.Label({text: 'secsec', style_class: 'message-dialog-title'}));
        box.add_child(new St.Label({
            text: `Unlock your SSH key to sync ${folder}`,
            style_class: 'message-dialog-description',
        }));

        this._entry = new St.Entry({can_focus: true, x_expand: true, style_class: 'secsec-pass-entry'});
        this._entry.clutter_text.set_password_char('●');
        this._entry.clutter_text.connect('activate', () => this._submit());
        box.add_child(this._entry);

        this.addButton({
            label: 'Cancel',
            action: () => this._cancel(),
            key: Clutter.KEY_Escape,
        });
        this.addButton({label: 'Unlock', action: () => this._submit(), default: true});
        this.setInitialKeyFocus(this._entry.clutter_text);
    }

    _submit() {
        if (this._done)
            return;
        this._done = true;
        const pw = this._entry.get_text();
        this.close(global.get_current_time());
        this._onSubmit(pw);
    }

    _cancel() {
        if (this._done)
            return;
        this._done = true;
        this.close(global.get_current_time());
        this._onCancel();
    }
});

const Indicator = GObject.registerClass(
class Indicator extends PanelMenu.Button {
    _init(ext) {
        super._init(0.0, 'secsec');
        this._ext = ext;

        // Retro LED status dot — the panel "icon" is the connect indicator (set in refresh()).
        this._dot = new St.Label({text: '○', y_align: Clutter.ActorAlign.CENTER});
        this.add_child(this._dot);

        this._status = new PopupMenu.PopupMenuItem('', {reactive: false, can_focus: false});
        this._status.label.clutter_text.set_line_wrap(true);
        this.menu.addMenuItem(this._status);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        this._toggle = new PopupMenu.PopupMenuItem('Start sync');
        this._toggle.connect('activate', () => this._ext.toggle());
        this.menu.addMenuItem(this._toggle);

        const restart = new PopupMenu.PopupMenuItem('Restart sync');
        restart.connect('activate', () => this._ext.restart());
        this.menu.addMenuItem(restart);

        const openLog = new PopupMenu.PopupMenuItem('Open log');
        openLog.connect('activate', () => this._ext.openLog());
        this.menu.addMenuItem(openLog);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        const settings = new PopupMenu.PopupMenuItem('Settings (folder · SSH key)…');
        settings.connect('activate', () => this._ext.openSettings());
        this.menu.addMenuItem(settings);

        // Refresh the status text each time the menu opens.
        this.menu.connect('open-state-changed', (_m, open) => {
            if (open)
                this.refresh();
        });
        this.refresh();
    }

    refresh() {
        const running = this._ext.isRunning();
        const status = healthFromLog(this._ext.logPath, running);
        const led = LED[status];
        this._dot.set_text(led.glyph);
        this._dot.set_style(`font-family: monospace; font-weight: bold; font-size: 14px; color: ${led.color};`);

        this._toggle.label.text = running ? 'Stop sync' : 'Start sync';
        const cfg = readConfig();
        const folder = expandPath(cfg.folder);
        const head = {
            connected: `secsec: connected · ${folder}`,
            connecting: `secsec: connecting… · ${folder}`,
            error: `secsec: problem · ${folder}`,
            stopped: `secsec: stopped · ${folder}`,
        }[status];
        const tail = lastLogLine(this._ext.logPath);
        this._status.label.text = tail ? `${head}\n${tail}` : head;
    }
});

export default class SecsecExtension extends Extension {
    enable() {
        this.logPath = logPath();
        this._proc = null;
        this._dialog = null;
        this._timeoutId = 0;
        this._pollId = 0;

        this._indicator = new Indicator(this);
        Main.panel.addToStatusArea(this.uuid, this._indicator);

        // Pop the login prompt shortly after the session settles. If the user cancels, they can
        // still start it from the menu later.
        this._timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, PROMPT_DELAY_MS, () => {
            this._timeoutId = 0;
            this.start();
            return GLib.SOURCE_REMOVE;
        });

        // Every 15 s: refresh the retro connect LED from process liveness + the log tail.
        this._pollId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 15, () => {
            this._indicator?.refresh();
            return GLib.SOURCE_CONTINUE;
        });
    }

    disable() {
        if (this._timeoutId) {
            GLib.source_remove(this._timeoutId);
            this._timeoutId = 0;
        }
        if (this._pollId) {
            GLib.source_remove(this._pollId);
            this._pollId = 0;
        }
        if (this._dialog) {
            this._dialog.close(global.get_current_time());
            this._dialog = null;
        }
        this.stop();
        this._indicator?.destroy();
        this._indicator = null;
    }

    isRunning() {
        return this._proc !== null;
    }

    openSettings() {
        this.openPreferences();
    }

    // Prompt (unless already running / already prompting) and start the sync child. Config is read
    // fresh here, so a folder/key changed in Settings takes effect on the next start or Restart.
    start() {
        if (this._proc || this._dialog)
            return;
        const cfg = readConfig();
        this._dialog = new PassphraseDialog(
            expandPath(cfg.folder),
            pw => {
                this._dialog = null;
                this._spawn(cfg.bin, cfg.folder, cfg.key, pw);
            },
            () => {
                this._dialog = null;
            });
        this._dialog.open(global.get_current_time());
    }

    _spawn(bin, folder, key, passphrase) {
        const argv = [bin, 'sync', expandPath(folder), '--passphrase-stdin'];
        if (key)
            argv.push('--key', expandPath(key));

        const launcher = new Gio.SubprocessLauncher({
            flags: Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDERR_MERGE,
        });
        launcher.set_stdout_file_path(this.logPath);
        let proc;
        try {
            proc = launcher.spawnv(argv);
        } catch (e) {
            Main.notifyError('secsec', `failed to start sync: ${e.message}`);
            return;
        }
        this._proc = proc;

        // Feed the passphrase over stdin, then close so `secsec` reads EOF. The secret only ever
        // travels this pipe — it is never an argument.
        const stdin = proc.get_stdin_pipe();
        try {
            stdin.write_all(new TextEncoder().encode(passphrase), null);
        } catch (_) {
            // best-effort; secsec will report a decrypt failure in the log
        }
        stdin.close(null);

        proc.wait_async(null, (p, res) => {
            try {
                p.wait_finish(res);
            } catch (_) {
            }
            if (this._proc === p)
                this._proc = null;
            this._indicator?.refresh();
        });
        this._indicator?.refresh();
    }

    stop() {
        if (!this._proc)
            return;
        try {
            this._proc.send_signal(15); // SIGTERM — let secsec close its connection cleanly
        } catch (_) {
            try {
                this._proc.force_exit();
            } catch (_) {
            }
        }
        this._proc = null;
        this._indicator?.refresh();
    }

    toggle() {
        if (this._proc)
            this.stop();
        else
            this.start();
    }

    restart() {
        this.stop();
        this.start();
    }

    openLog() {
        try {
            Gio.AppInfo.launch_default_for_uri(`file://${this.logPath}`, null);
        } catch (e) {
            Main.notifyError('secsec', `cannot open log: ${e.message}`);
        }
    }
}
