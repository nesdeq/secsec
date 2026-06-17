// secsec — macOS menu-bar agent.
//
// A thin shell around the `secsec` binary: at login it prompts for the SSH-key passphrase, spawns
// `secsec sync <folder> --passphrase-stdin [--key <keyfile>]`, and feeds the passphrase over the
// child's stdin pipe — so the secret never appears in argv (invisible to `ps`/`top`). The child's
// stdout+stderr go to ~/.config/secsec/ui/sync.log. A retro LED in the menu bar shows the connect
// status (refreshed every 15 s from process liveness + the log). Folder and SSH key are set from the
// menu via native file pickers.
//
// Config: ~/.config/secsec/ui.conf — `folder=<path>` (default ~/cloud), optional `key=<ssh key>`,
// optional `bin=<path to secsec>`. The folder must already be linked by a manual first
// `secsec sync <folder> --server …`. `~` is expanded in `folder` and `key`.
//
// Build: ./build.sh  (or `swiftc -O secsec-menubar.swift -o secsec-menubar`).

import Cocoa

// ---- config + paths ----

func home() -> String { NSHomeDirectory() }

func expandTilde(_ p: String) -> String {
    if p == "~" { return home() }
    if p.hasPrefix("~/") { return home() + String(p.dropFirst(1)) }
    return p
}

struct Config {
    var folder: String = "~/cloud"
    var key: String = ""
    var bin: String = "secsec"
}

let configPath = "\(home())/.config/secsec/ui.conf"

func readConfig() -> Config {
    var cfg = Config()
    guard let text = try? String(contentsOfFile: configPath, encoding: .utf8) else { return cfg }
    for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") { continue }
        guard let eq = line.firstIndex(of: "=") else { continue }
        let key = line[..<eq].trimmingCharacters(in: .whitespaces)
        let val = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
        switch key {
        case "folder": if !val.isEmpty { cfg.folder = val }
        case "key": cfg.key = val
        case "bin": if !val.isEmpty { cfg.bin = val }
        default: break
        }
    }
    return cfg
}

func writeConfig(_ cfg: Config) {
    let dir = "\(home())/.config/secsec"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    var body = "# secsec desktop UI config (managed by the secsec UI)\n"
    body += "folder=\(cfg.folder)\n"
    if !cfg.key.isEmpty { body += "key=\(cfg.key)\n" }
    if cfg.bin != "secsec" { body += "bin=\(cfg.bin)\n" }
    try? body.write(toFile: configPath, atomically: true, encoding: .utf8)
}

// Kept under ~/.config/secsec/ alongside ui.conf so the UI's files don't scatter.
func logURL() -> URL {
    let dir = URL(fileURLWithPath: "\(home())/.config/secsec/ui")
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("sync.log")
}

// Resolve the secsec binary: the configured path, then the usual install dirs, else fall back to a
// PATH search via /usr/bin/env (a GUI agent's PATH is minimal, so we resolve explicitly first).
func resolveBinary(_ configured: String) -> (exec: URL, args: [String]) {
    let fm = FileManager.default
    var candidates = [String]()
    let c = expandTilde(configured)
    if c.contains("/") { candidates.append(c) }
    candidates.append("/usr/local/bin/secsec")
    candidates.append("\(home())/.local/bin/secsec")
    candidates.append("/opt/homebrew/bin/secsec")
    for cand in candidates where fm.isExecutableFile(atPath: cand) {
        return (URL(fileURLWithPath: cand), [])
    }
    return (URL(fileURLWithPath: "/usr/bin/env"), [configured])
}

func lastLogLine(_ url: URL) -> String {
    guard let text = try? String(contentsOf: url, encoding: .utf8) else { return "" }
    let lines = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { !$0.isEmpty }
    return lines.last ?? ""
}

// ---- connect health (the 15 s poll) ----

enum Health { case connected, connecting, error, stopped }

// Scan the log newest-first: a hard error marker → .error, a transient "connection lost" →
// .connecting, a healthy sync line → .connected; a running process with nothing notable → .connected.
func health(running: Bool, log: URL) -> Health {
    if !running { return .stopped }
    guard let text = try? String(contentsOf: log, encoding: .utf8) else { return .connected }
    let hard = ["reconnect failed", "sync error", "alarm", "wrong passphrase", "could not", "no server"]
    let warn = ["connection lost"]
    let ok = ["watching", "sync: uptodate", "sync: pushed", "sync: pulled", "sync: merged",
              "sync: published", "sync: cloned", "synced "]
    for raw in text.split(separator: "\n").reversed() {
        let line = raw.lowercased()
        if hard.contains(where: { line.contains($0) }) { return .error }
        if warn.contains(where: { line.contains($0) }) { return .connecting }
        if ok.contains(where: { line.contains($0) }) { return .connected }
    }
    return .connected
}

// ---- app ----

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var statusLine: NSMenuItem!
    private var toggleItem: NSMenuItem!
    private var task: Process?
    private var pollTimer: Timer?
    private let log = logURL()

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory) // menu-bar agent, no Dock icon

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        buildMenu()
        refresh()
        promptAndStart()

        // Poll every 15 s: refresh the retro connect LED from process liveness + the log.
        pollTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func applicationWillTerminate(_ note: Notification) {
        pollTimer?.invalidate()
        stop()
    }

    private func buildMenu() {
        let menu = NSMenu()
        menu.delegate = self

        statusLine = NSMenuItem(title: "secsec: stopped", action: nil, keyEquivalent: "")
        statusLine.isEnabled = false
        menu.addItem(statusLine)
        menu.addItem(.separator())

        toggleItem = NSMenuItem(title: "Start sync", action: #selector(toggle), keyEquivalent: "")
        toggleItem.target = self
        menu.addItem(toggleItem)

        let restart = NSMenuItem(title: "Restart sync", action: #selector(restart), keyEquivalent: "")
        restart.target = self
        menu.addItem(restart)

        let openLog = NSMenuItem(title: "Open log", action: #selector(openLog), keyEquivalent: "")
        openLog.target = self
        menu.addItem(openLog)

        menu.addItem(.separator())
        let setFolder = NSMenuItem(title: "Set sync folder…", action: #selector(chooseFolder), keyEquivalent: "")
        setFolder.target = self
        menu.addItem(setFolder)
        let setKey = NSMenuItem(title: "Select SSH key…", action: #selector(chooseKey), keyEquivalent: "")
        setKey.target = self
        menu.addItem(setKey)
        let defKey = NSMenuItem(title: "Use default key (~/.ssh/id_ed25519)", action: #selector(clearKey), keyEquivalent: "")
        defKey.target = self
        menu.addItem(defKey)

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit (stop sync)", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        statusItem.menu = menu
    }

    private var isRunning: Bool { task?.isRunning ?? false }

    private func refresh() {
        let h = health(running: isRunning, log: log)
        let (glyph, color): (String, NSColor) = {
            switch h {
            case .connected: return ("●", NSColor(srgbRed: 0.20, green: 1.00, blue: 0.40, alpha: 1))
            case .connecting: return ("●", NSColor(srgbRed: 1.00, green: 0.80, blue: 0.20, alpha: 1))
            case .error: return ("●", NSColor(srgbRed: 1.00, green: 0.23, blue: 0.19, alpha: 1))
            case .stopped: return ("○", NSColor(srgbRed: 0.60, green: 0.63, blue: 0.65, alpha: 1))
            }
        }()
        if let button = statusItem.button {
            button.image = nil
            button.attributedTitle = NSAttributedString(string: glyph, attributes: [
                .foregroundColor: color,
                .font: NSFont.monospacedSystemFont(ofSize: 13, weight: .bold),
            ])
        }
        toggleItem.title = isRunning ? "Stop sync" : "Start sync"
        let folder = expandTilde(readConfig().folder)
        let head: String = {
            switch h {
            case .connected: return "secsec: connected — \(folder)"
            case .connecting: return "secsec: connecting… — \(folder)"
            case .error: return "secsec: problem — \(folder)"
            case .stopped: return "secsec: stopped — \(folder)"
            }
        }()
        let tail = lastLogLine(log)
        statusLine.title = tail.isEmpty ? head : "\(head) — \(tail)"
    }

    // Prompt for the passphrase (masked) and start the sync child. Config is read fresh, so a
    // folder/key changed from the menu takes effect on the next start/restart.
    private func promptAndStart() {
        if isRunning { return }
        let cfg = readConfig()
        guard let pass = promptPassphrase(folder: expandTilde(cfg.folder)) else {
            refresh() // cancelled — user can Start from the menu later
            return
        }
        spawn(cfg, passphrase: pass)
    }

    private func promptPassphrase(folder: String) -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "secsec"
        alert.informativeText = "Unlock your SSH key to sync \(folder)"
        alert.addButton(withTitle: "Unlock")
        alert.addButton(withTitle: "Cancel")
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 240, height: 24))
        alert.accessoryView = field
        alert.window.initialFirstResponder = field
        let resp = alert.runModal()
        return resp == .alertFirstButtonReturn ? field.stringValue : nil
    }

    private func spawn(_ cfg: Config, passphrase: String) {
        let (exec, prefix) = resolveBinary(cfg.bin)
        let proc = Process()
        proc.executableURL = exec
        var args = prefix + ["sync", expandTilde(cfg.folder), "--passphrase-stdin"]
        if !cfg.key.isEmpty { args += ["--key", expandTilde(cfg.key)] }
        proc.arguments = args

        // Fresh log per launch; stdout+stderr both go to it.
        FileManager.default.createFile(atPath: log.path, contents: nil)
        guard let logHandle = try? FileHandle(forWritingTo: log) else {
            notify("cannot open log file \(log.path)")
            return
        }
        proc.standardOutput = logHandle
        proc.standardError = logHandle

        let stdinPipe = Pipe()
        proc.standardInput = stdinPipe

        proc.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.task = nil
                self?.refresh()
            }
        }
        do {
            try proc.run()
        } catch {
            notify("failed to start sync: \(error.localizedDescription)")
            return
        }
        task = proc

        // Feed the passphrase over stdin, then close so `secsec` reads EOF. The secret only ever
        // travels this pipe — it is never an argument.
        if let data = passphrase.data(using: .utf8) {
            try? stdinPipe.fileHandleForWriting.write(contentsOf: data)
        }
        try? stdinPipe.fileHandleForWriting.close()
        refresh()
    }

    private func stop() {
        guard let proc = task, proc.isRunning else { task = nil; return }
        proc.terminate() // SIGTERM — let secsec close its connection cleanly
        task = nil
    }

    // Re-launch with current config (after a folder/key change) only if a sync is already running.
    private func reloadIfRunning() {
        if isRunning {
            stop()
            promptAndStart()
        } else {
            refresh()
        }
    }

    @objc private func toggle() {
        if isRunning { stop(); refresh() } else { promptAndStart() }
    }

    @objc private func restart() {
        stop()
        promptAndStart()
    }

    @objc private func openLog() {
        NSWorkspace.shared.open(log)
    }

    @objc private func chooseFolder() {
        var cfg = readConfig()
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Choose"
        panel.message = "Choose the folder to keep in sync"
        panel.directoryURL = URL(fileURLWithPath: expandTilde(cfg.folder))
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK, let url = panel.url {
            cfg.folder = url.path
            writeConfig(cfg)
            reloadIfRunning()
        }
    }

    @objc private func chooseKey() {
        var cfg = readConfig()
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        panel.prompt = "Select"
        panel.message = "Select your SSH private key"
        panel.directoryURL = URL(fileURLWithPath: "\(home())/.ssh")
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK, let url = panel.url {
            cfg.key = url.path
            writeConfig(cfg)
            reloadIfRunning()
        }
    }

    @objc private func clearKey() {
        var cfg = readConfig()
        cfg.key = ""
        writeConfig(cfg)
        reloadIfRunning()
    }

    @objc private func quit() {
        stop()
        NSApp.terminate(nil)
    }

    private func notify(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "secsec"
        alert.informativeText = message
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}

extension AppDelegate: NSMenuDelegate {
    func menuWillOpen(_ menu: NSMenu) { refresh() }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
