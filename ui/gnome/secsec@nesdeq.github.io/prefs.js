// secsec preferences window (GNOME 45+): edits the sync folder and SSH key in secsec/ui.conf under the user config dir; changes apply on the next start.

import Adw from 'gi://Adw';
import Gtk from 'gi://Gtk';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

import {ExtensionPreferences} from 'resource:///org/gnome/Shell/Extensions/js/extensions/prefs.js';

function configDir() {
    return GLib.build_filenamev([GLib.get_user_config_dir(), 'secsec']);
}

function configPath() {
    return GLib.build_filenamev([configDir(), 'ui.conf']);
}

function defaultFolder() {
    return GLib.build_filenamev([GLib.get_home_dir(), 'cloud']);
}

function readConfig() {
    const cfg = {folder: '', key: '', bin: ''};
    let bytes;
    try {
        [, bytes] = GLib.file_get_contents(configPath());
    } catch (_) {
        return cfg;
    }
    for (let line of new TextDecoder().decode(bytes).split('\n')) {
        line = line.trim();
        if (!line || line.startsWith('#'))
            continue;
        const eq = line.indexOf('=');
        if (eq < 0)
            continue;
        const k = line.slice(0, eq).trim();
        const v = line.slice(eq + 1).trim();
        if (k === 'folder')
            cfg.folder = v;
        else if (k === 'key')
            cfg.key = v;
        else if (k === 'bin')
            cfg.bin = v;
    }
    return cfg;
}

// Write ui.conf owner-only inside the owner-only secsec config directory.
function writeConfig(cfg) {
    GLib.mkdir_with_parents(configDir(), 0o700);
    let body = '# secsec desktop UI config (managed by the secsec UI)\n';
    body += `folder=${cfg.folder || ''}\n`;
    if (cfg.key)
        body += `key=${cfg.key}\n`;
    if (cfg.bin)
        body += `bin=${cfg.bin}\n`;
    GLib.file_set_contents_full(configPath(), body, GLib.FileSetContentsFlags.CONSISTENT, 0o600);
}

export default class SecsecPrefs extends ExtensionPreferences {
    fillPreferencesWindow(window) {
        const cfg = readConfig();

        const page = new Adw.PreferencesPage();
        const group = new Adw.PreferencesGroup({
            title: 'Sync',
            description:
                'Link the folder once from a terminal first (`secsec sync <folder> --server <host> --pin <host pin> --once`). ' +
                'Changes apply on the next Start or Restart.',
        });
        page.add(group);

        const folderRow = new Adw.EntryRow({title: 'Folder', show_apply_button: true});
        folderRow.text = cfg.folder || defaultFolder();
        const folderBtn = new Gtk.Button({icon_name: 'folder-open-symbolic', valign: Gtk.Align.CENTER});
        folderBtn.add_css_class('flat');
        folderRow.add_suffix(folderBtn);
        group.add(folderRow);

        const keyRow = new Adw.EntryRow({
            title: 'SSH key (blank = ~/.ssh/id_ed25519)',
            show_apply_button: true,
        });
        keyRow.text = cfg.key || '';
        const keyBtn = new Gtk.Button({icon_name: 'document-open-symbolic', valign: Gtk.Align.CENTER});
        keyBtn.add_css_class('flat');
        keyRow.add_suffix(keyBtn);
        group.add(keyRow);

        const save = () => writeConfig({
            folder: folderRow.text.trim(),
            key: keyRow.text.trim(),
            bin: cfg.bin,
        });
        folderRow.connect('apply', save);
        keyRow.connect('apply', save);
        window.connect('close-request', () => {
            save();
            return false;
        });

        folderBtn.connect('clicked', () => {
            const dialog = new Gtk.FileDialog({title: 'Choose the sync folder', modal: true});
            dialog.select_folder(window, null, (src, res) => {
                try {
                    const file = src.select_folder_finish(res);
                    if (file) {
                        folderRow.text = file.get_path();
                        save();
                    }
                } catch (_) {
                    // cancelled
                }
            });
        });

        keyBtn.connect('clicked', () => {
            const dialog = new Gtk.FileDialog({title: 'Choose your SSH private key', modal: true});
            dialog.set_initial_folder(Gio.File.new_for_path(
                GLib.build_filenamev([GLib.get_home_dir(), '.ssh'])));
            dialog.open(window, null, (src, res) => {
                try {
                    const file = src.open_finish(res);
                    if (file) {
                        keyRow.text = file.get_path();
                        save();
                    }
                } catch (_) {
                    // cancelled
                }
            });
        });

        window.add(page);
    }
}
