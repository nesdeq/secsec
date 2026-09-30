// secsec GNOME Shell extension (GNOME 45+): runs `secsec sync` for one folder, feeding the key passphrase over a pipe, and shows its status.

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

const PROMPT_DELAY_MS = 1200; // let the session settle before the login prompt
const SPAWN_DELAY_MS = 10000; // after the passphrase, give the network time to come up before secsec connects
const POLL_SECONDS = 15; // status refresh cadence

function expandPath(p) {
    if (!p)
        return p;
    if (p === '~')
        return GLib.get_home_dir();
    if (p.startsWith('~/'))
        return GLib.build_filenamev([GLib.get_home_dir(), p.slice(2)]);
    return p;
}

function configDir() {
    return GLib.build_filenamev([GLib.get_user_config_dir(), 'secsec']);
}

// secsec/ui.conf under the user config dir as {folder, key, bin}; a blank folder means ~/cloud, a blank key the default SSH key.
function readConfig() {
    const cfg = {folder: '', bin: 'secsec', key: ''};
    let bytes = null;
    try {
        [, bytes] = GLib.file_get_contents(GLib.build_filenamev([configDir(), 'ui.conf']));
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
        cfg.folder = GLib.build_filenamev([GLib.get_home_dir(), 'cloud']);
    return cfg;
}

// The configured binary, else the first secsec on PATH or in the installer's directories.
function resolveBin(configured) {
    const c = expandPath(configured);
    if (c.includes('/'))
        return c;
    const onPath = GLib.find_program_in_path(c);
    if (onPath)
        return onPath;
    for (const cand of [GLib.build_filenamev([GLib.get_home_dir(), '.local', 'bin', c]), `/usr/local/bin/${c}`]) {
        if (GLib.file_test(cand, GLib.FileTest.IS_EXECUTABLE))
            return cand;
    }
    return c;
}

// The sync log, in an owner-only directory beside ui.conf.
function logPath() {
    const dir = GLib.build_filenamev([configDir(), 'ui']);
    GLib.mkdir_with_parents(dir, 0o700);
    GLib.chmod(dir, 0o700);
    return GLib.build_filenamev([dir, 'sync.log']);
}

// Start the log empty and owner-only, so the child's output is never readable by others.
function resetLog(path) {
    try {
        GLib.file_set_contents_full(path, '', GLib.FileSetContentsFlags.NONE, 0o600);
        GLib.chmod(path, 0o600);
    } catch (_) {
        // the child's own launch reports an unwritable log
    }
}

// Run `secsec <args>` and pass its stdout to done(); a failure passes ''.
function runSecsec(bin, args, done) {
    let proc;
    try {
        proc = Gio.Subprocess.new([resolveBin(bin), ...args],
            Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_SILENCE);
    } catch (_) {
        done('');
        return;
    }
    proc.communicate_utf8_async(null, null, (p, res) => {
        let out = '';
        try {
            [, out] = p.communicate_utf8_finish(res);
        } catch (_) {
            out = '';
        }
        done(out || '');
    });
}

// `secsec status` key=value lines as an object.
function parseStatus(text) {
    const st = {};
    for (const line of text.split('\n')) {
        const eq = line.indexOf('=');
        if (eq > 0)
            st[line.slice(0, eq)] = line.slice(eq + 1);
    }
    return st;
}

// Panel health from a status: stopped, error, connecting, or connected.
function health(st, ownChild) {
    if (st.running !== 'yes')
        return ownChild ? 'connecting' : 'stopped';
    if (st.state === 'error' || st.state === 'alarm')
        return 'error';
    if (['starting', 'connecting', 'stopping'].includes(st.state))
        return 'connecting';
    return 'connected';
}

// A modal asking for the key passphrase; the entry is cleared as soon as it is read.
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

        this.addButton({label: 'Cancel', action: () => this._cancel(), key: Clutter.KEY_Escape});
        this.addButton({label: 'Unlock', action: () => this._submit(), default: true});
        this.setInitialKeyFocus(this._entry.clutter_text);
    }

    _submit() {
        if (this._done)
            return;
        this._done = true;
        const pw = this._entry.get_text();
        this._entry.set_text('');
        this.close(global.get_current_time());
        this._onSubmit(pw);
    }

    _cancel() {
        if (this._done)
            return;
        this._done = true;
        this._entry.set_text('');
        this.close(global.get_current_time());
        this._onCancel();
    }
});

const Indicator = GObject.registerClass(
class Indicator extends PanelMenu.Button {
    _init(ext) {
        super._init(0.0, 'secsec');
        this._ext = ext;

        // The mark's bar is green while connected and syncing, orange otherwise.
        this._icon = new St.Icon({icon_size: 16, y_align: Clutter.ActorAlign.CENTER});
        this.add_child(this._icon);

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

        this.menu.connect('open-state-changed', (_m, open) => {
            if (open)
                this._ext.refresh();
        });
        this.show({running: 'no'}, false);
    }

    show(st, ownChild) {
        const h = health(st, ownChild);
        const file = h === 'connected' ? 'secsec-syncing.svg' : 'secsec-idle.svg';
        this._icon.set_gicon(Gio.icon_new_for_string(
            GLib.build_filenamev([this._ext.path, 'icons', file])));
        this._toggle.label.text = h === 'stopped' ? 'Start sync' : 'Stop sync';
        const folder = expandPath(readConfig().folder);
        const head = {
            connected: `secsec: connected · ${folder}`,
            connecting: `secsec: connecting… · ${folder}`,
            error: `secsec: problem · ${folder}`,
            stopped: `secsec: stopped · ${folder}`,
        }[h];
        this._status.label.text = st.message ? `${head}\n${st.message}` : head;
    }
});

export default class SecsecExtension extends Extension {
    enable() {
        this.logPath = logPath();
        this._proc = null;
        this._dialog = null;
        this._timeoutId = 0;
        this._pollId = 0;
        this._spawnTimeoutId = 0;
        this._status = {running: 'no'};

        this._indicator = new Indicator(this);
        Main.panel.addToStatusArea(this.uuid, this._indicator);

        // The sync keeps running on the lock screen; only the panel UI hides there.
        this._sessionId = Main.sessionMode.connect('updated', () => this._applySessionMode());
        this._applySessionMode();

        this._timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, PROMPT_DELAY_MS, () => {
            this._timeoutId = 0;
            this.start();
            return GLib.SOURCE_REMOVE;
        });
        this._pollId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, POLL_SECONDS, () => {
            this.refresh();
            return GLib.SOURCE_CONTINUE;
        });
        this.refresh();
    }

    disable() {
        for (const id of [this._timeoutId, this._pollId, this._spawnTimeoutId]) {
            if (id)
                GLib.source_remove(id);
        }
        this._timeoutId = 0;
        this._pollId = 0;
        this._spawnTimeoutId = 0;
        if (this._sessionId) {
            Main.sessionMode.disconnect(this._sessionId);
            this._sessionId = 0;
        }
        if (this._dialog) {
            this._dialog.close(global.get_current_time());
            this._dialog = null;
        }
        if (this._proc) {
            this._proc.send_signal(15);
            this._proc = null;
        }
        this._indicator?.destroy();
        this._indicator = null;
    }

    _applySessionMode() {
        const locked = Main.sessionMode.isLocked;
        if (this._indicator)
            this._indicator.visible = !locked;
        if (locked && this._dialog) {
            this._dialog.close(global.get_current_time());
            this._dialog = null;
        }
    }

    refresh() {
        const cfg = readConfig();
        runSecsec(cfg.bin, ['status', expandPath(cfg.folder)], out => {
            this._status = parseStatus(out);
            this._indicator?.show(this._status, this._proc !== null);
        });
    }

    isRunning() {
        return this._proc !== null || this._status.running === 'yes';
    }

    openSettings() {
        this.openPreferences();
    }

    // Stop whatever sync holds the folder (secsec signals it by its lock pid and waits), then continue.
    _stopFolderSync(cfg, next) {
        runSecsec(cfg.bin, ['stop', expandPath(cfg.folder)], () => next());
    }

    start() {
        if (this._proc || this._dialog || this._spawnTimeoutId || Main.sessionMode.isLocked)
            return;
        const cfg = readConfig();
        this._dialog = new PassphraseDialog(
            expandPath(cfg.folder),
            pw => {
                this._dialog = null;
                this._stopFolderSync(cfg, () => {
                    resetLog(this.logPath);
                    this.refresh();
                    this._spawnTimeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, SPAWN_DELAY_MS, () => {
                        this._spawnTimeoutId = 0;
                        this._spawn(cfg, pw);
                        pw = null;
                        return GLib.SOURCE_REMOVE;
                    });
                });
            },
            () => {
                this._dialog = null;
            });
        this._dialog.open(global.get_current_time());
    }

    _spawn(cfg, passphrase) {
        const argv = [resolveBin(cfg.bin), 'sync', expandPath(cfg.folder), '--passphrase-stdin'];
        if (cfg.key)
            argv.push('--key', expandPath(cfg.key));

        const launcher = new Gio.SubprocessLauncher({
            flags: Gio.SubprocessFlags.STDIN_PIPE | Gio.SubprocessFlags.STDERR_MERGE,
        });
        launcher.set_stdout_file_path(this.logPath);
        launcher.set_cwd(GLib.get_home_dir());
        for (const v of ['NOTIFY_SOCKET', 'JOURNAL_STREAM', 'INVOCATION_ID', 'MEMORY_PRESSURE_WATCH',
            'SYSTEMD_EXEC_PID', 'WATCHDOG_PID', 'WATCHDOG_USEC', 'LISTEN_PID', 'LISTEN_FDS',
            'LISTEN_FDNAMES'])
            launcher.unsetenv(v);
        let proc;
        try {
            proc = launcher.spawnv(argv);
        } catch (e) {
            Main.notifyError('secsec', `failed to start sync: ${e.message}`);
            return;
        }
        this._proc = proc;

        // The passphrase only ever travels this pipe; its bytes are zeroed once written.
        const stdin = proc.get_stdin_pipe();
        const bytes = new TextEncoder().encode(passphrase);
        try {
            stdin.write_all(bytes, null);
        } catch (_) {
            // secsec reports a failed decrypt in the log
        }
        bytes.fill(0);
        stdin.close(null);

        proc.wait_async(null, (p, res) => {
            try {
                p.wait_finish(res);
            } catch (_) {
            }
            if (this._proc === p)
                this._proc = null;
            this.refresh();
        });
        this.refresh();
    }

    stop() {
        if (this._spawnTimeoutId) {
            GLib.source_remove(this._spawnTimeoutId);
            this._spawnTimeoutId = 0;
        }
        if (this._proc) {
            this._proc.send_signal(15);
            this._proc = null;
            this.refresh();
        } else {
            this._stopFolderSync(readConfig(), () => this.refresh());
        }
    }

    toggle() {
        if (this.isRunning())
            this.stop();
        else
            this.start();
    }

    restart() {
        if (this._spawnTimeoutId) {
            GLib.source_remove(this._spawnTimeoutId);
            this._spawnTimeoutId = 0;
        }
        if (this._proc) {
            this._proc.send_signal(15);
            this._proc = null;
        }
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
