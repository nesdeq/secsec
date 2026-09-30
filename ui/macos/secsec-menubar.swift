// secsec macOS menu-bar agent: runs `secsec sync` for one folder, feeding the key passphrase over a pipe, and shows its status; build with ./build.sh.

import Cocoa

// ---- config and paths ----

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

// The secsec binary's client root: $XDG_CONFIG_HOME/secsec when that is absolute, else ~/.config/secsec.
let configDir: String = {
    if let x = ProcessInfo.processInfo.environment["XDG_CONFIG_HOME"], x.hasPrefix("/") { return "\(x)/secsec" }
    return "\(home())/.config/secsec"
}()
let configPath = "\(configDir)/ui.conf"
let logURL = URL(fileURLWithPath: "\(configDir)/ui/sync.log")

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

// Write ui.conf owner-only inside the owner-only secsec config directory.
func writeConfig(_ cfg: Config) {
    let fm = FileManager.default
    try? fm.createDirectory(atPath: configDir, withIntermediateDirectories: true,
                            attributes: [.posixPermissions: 0o700])
    var body = "# secsec desktop UI config (managed by the secsec UI)\n"
    body += "folder=\(cfg.folder)\n"
    if !cfg.key.isEmpty { body += "key=\(cfg.key)\n" }
    if cfg.bin != "secsec" { body += "bin=\(cfg.bin)\n" }
    try? body.write(toFile: configPath, atomically: true, encoding: .utf8)
    try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath)
}

// A fresh, empty, owner-only log in an owner-only directory, for one launch.
func freshLog() -> FileHandle? {
    let fm = FileManager.default
    let dir = logURL.deletingLastPathComponent().path
    try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true,
                            attributes: [.posixPermissions: 0o700])
    try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
    guard fm.createFile(atPath: logURL.path, contents: nil,
                        attributes: [.posixPermissions: 0o600]) else { return nil }
    try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: logURL.path)
    return try? FileHandle(forWritingTo: logURL)
}

// The configured binary, else the usual install directories, else a PATH search (a GUI agent's PATH is minimal).
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

// Run `secsec <args>` to completion and return its stdout; it blocks, so it runs off the main thread.
func runSecsec(_ cfg: Config, _ args: [String]) -> String {
    let (exec, prefix) = resolveBinary(cfg.bin)
    let p = Process()
    p.executableURL = exec
    p.arguments = prefix + args
    let out = Pipe()
    p.standardOutput = out
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return "" }
    let data = out.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(data: data, encoding: .utf8) ?? ""
}

// ---- status ----

enum Health { case connected, connecting, error, stopped }

struct SyncStatus {
    var running = false
    var state = "stopped"
    var message = ""
}

// `secsec status` key=value lines.
func parseStatus(_ text: String) -> SyncStatus {
    var s = SyncStatus()
    for line in text.split(separator: "\n") {
        guard let eq = line.firstIndex(of: "=") else { continue }
        let key = String(line[..<eq])
        let val = String(line[line.index(after: eq)...])
        switch key {
        case "running": s.running = val == "yes"
        case "state": s.state = val
        case "message": s.message = val
        default: break
        }
    }
    return s
}

func health(_ s: SyncStatus, ownChild: Bool) -> Health {
    if !s.running { return ownChild ? .connecting : .stopped }
    switch s.state {
    case "error", "alarm": return .error
    case "starting", "connecting", "stopping": return .connecting
    default: return .connected
    }
}

// ---- session passphrase cache ----

// The session passphrase in RAM only, XOR-masked and mlock'd, so a wake can relaunch the sync without a prompt.
final class SecretCache {
    private var data: UnsafeMutableRawPointer?
    private var mask: UnsafeMutableRawPointer?
    private var len = 0
    private var entered = false

    // Whether a passphrase was entered this session; an empty one (a key without a passphrase) counts.
    var unlocked: Bool { entered }

    func store(_ s: String) {
        clear()
        entered = true
        var plain = Array(s.utf8)
        len = plain.count
        guard len > 0 else { return }
        let d = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: 1)
        let m = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: 1)
        _ = mlock(d, len); _ = mlock(m, len)
        arc4random_buf(m, len)
        let dp = d.assumingMemoryBound(to: UInt8.self)
        let mp = m.assumingMemoryBound(to: UInt8.self)
        for i in 0..<len { dp[i] = plain[i] ^ mp[i] }
        for i in plain.indices { plain[i] = 0 }
        data = d; mask = m
    }

    func reveal() -> Data? {
        guard let data, let mask, len > 0 else { return nil }
        let dp = data.assumingMemoryBound(to: UInt8.self)
        let mp = mask.assumingMemoryBound(to: UInt8.self)
        var out = [UInt8](repeating: 0, count: len)
        for i in 0..<len { out[i] = dp[i] ^ mp[i] }
        return Data(out)
    }

    func clear() {
        if let data { _ = memset(data, 0, len); _ = munlock(data, len); data.deallocate() }
        if let mask { _ = memset(mask, 0, len); _ = munlock(mask, len); mask.deallocate() }
        data = nil; mask = nil; len = 0; entered = false
    }
}

// ---- app ----

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var statusLine: NSMenuItem!
    private var toggleItem: NSMenuItem!
    private var task: Process?
    private var pollTimer: Timer?
    private let cache = SecretCache()
    private var intendRunning = false
    private var lastStatus = SyncStatus()
    private let worker = DispatchQueue(label: "secsec.ui.worker")

    func applicationDidFinishLaunching(_ note: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        buildMenu()
        redraw()
        promptAndStart()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in
            self?.refresh()
        }
        // After sleep the child's runtime timers are wedged; a wake relaunches it.
        NSWorkspace.shared.notificationCenter.addObserver(
            self, selector: #selector(systemDidWake(_:)),
            name: NSWorkspace.didWakeNotification, object: nil)
    }

    func applicationWillTerminate(_ note: Notification) {
        pollTimer?.invalidate()
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        intendRunning = false
        if let proc = task, proc.isRunning { proc.terminate() }
        cache.clear()
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

    private var ownChild: Bool { task?.isRunning ?? false }
    private var isRunning: Bool { ownChild || lastStatus.running }

    // The menu-bar mark: a white diagonal crossed by the status bar, green when connected, orange otherwise.
    private static func markImage(connected: Bool) -> NSImage {
        let px: CGFloat = 18
        let img = NSImage(size: NSSize(width: px, height: px))
        img.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .high
        let k = px / 64.0
        func point(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: x * k, y: (64 - y) * k) }
        func stroke(_ a: NSPoint, _ b: NSPoint, _ color: NSColor) {
            let p = NSBezierPath()
            p.move(to: a); p.line(to: b)
            p.lineWidth = 7 * k; p.lineCapStyle = .round
            color.setStroke(); p.stroke()
        }
        stroke(point(17.858, 46.142), point(46.142, 17.858), .white)
        let bar = connected
            ? NSColor(srgbRed: 0x2a / 255.0, green: 0xa8 / 255.0, blue: 0x5a / 255.0, alpha: 1)
            : NSColor(srgbRed: 0xe0 / 255.0, green: 0x8a / 255.0, blue: 0x30 / 255.0, alpha: 1)
        stroke(point(12, 32), point(52, 32), bar)
        img.unlockFocus()
        img.isTemplate = false
        return img
    }

    // Ask `secsec status` off the main thread, then redraw.
    private func refresh() {
        let cfg = readConfig()
        worker.async { [weak self] in
            let s = parseStatus(runSecsec(cfg, ["status", expandTilde(cfg.folder)]))
            DispatchQueue.main.async {
                self?.lastStatus = s
                self?.redraw()
            }
        }
    }

    private func redraw() {
        let h = health(lastStatus, ownChild: ownChild)
        if let button = statusItem.button {
            button.attributedTitle = NSAttributedString(string: "")
            button.image = Self.markImage(connected: h == .connected)
            button.imagePosition = .imageOnly
        }
        toggleItem.title = isRunning ? "Stop sync" : "Start sync"
        let folder = expandTilde(readConfig().folder)
        let head: String = {
            switch h {
            case .connected: return "secsec: connected · \(folder)"
            case .connecting: return "secsec: connecting… · \(folder)"
            case .error: return "secsec: problem · \(folder)"
            case .stopped: return "secsec: stopped · \(folder)"
            }
        }()
        statusLine.title = lastStatus.message.isEmpty ? head : "\(head) · \(lastStatus.message)"
    }

    // Stop whatever sync holds the configured folder (secsec signals it by its lock pid and waits), then continue on the main thread.
    private func stopFolderSync(then next: @escaping () -> Void) {
        let cfg = readConfig()
        worker.async {
            _ = runSecsec(cfg, ["stop", expandTilde(cfg.folder)])
            DispatchQueue.main.async(execute: next)
        }
    }

    // Prompt for the passphrase, cache it for the session, stop any sync of the folder, spawn.
    private func promptAndStart() {
        let cfg = readConfig()
        guard let pass = promptPassphrase(folder: expandTilde(cfg.folder)) else {
            intendRunning = false
            refresh()
            return
        }
        cache.store(pass)
        intendRunning = true
        stopFolderSync { [weak self] in self?.spawn(readConfig()) }
    }

    // Relaunch from the cached passphrase when there is one, else prompt.
    private func startFromCacheOrPrompt() {
        guard cache.unlocked else { promptAndStart(); return }
        intendRunning = true
        stopFolderSync { [weak self] in self?.spawn(readConfig()) }
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
        let value = field.stringValue
        field.stringValue = ""
        return resp == .alertFirstButtonReturn ? value : nil
    }

    private func spawn(_ cfg: Config) {
        let (exec, prefix) = resolveBinary(cfg.bin)
        let proc = Process()
        proc.executableURL = exec
        var args = prefix + ["sync", expandTilde(cfg.folder), "--passphrase-stdin"]
        if !cfg.key.isEmpty { args += ["--key", expandTilde(cfg.key)] }
        proc.arguments = args

        guard let logHandle = freshLog() else {
            notify("cannot open log file \(logURL.path)")
            return
        }
        proc.standardOutput = logHandle
        proc.standardError = logHandle
        let stdinPipe = Pipe()
        proc.standardInput = stdinPipe

        proc.terminationHandler = { [weak self] p in
            DispatchQueue.main.async {
                guard let self else { return }
                if self.task === p {
                    self.task = nil
                    self.refresh()
                }
            }
        }
        do {
            try proc.run()
        } catch {
            notify("failed to start sync: \(error.localizedDescription)")
            return
        }
        task = proc

        // The passphrase only ever travels this pipe; the plaintext copy is scrubbed once written.
        if var pass = cache.reveal() {
            try? stdinPipe.fileHandleForWriting.write(contentsOf: pass)
            pass.resetBytes(in: 0..<pass.count)
        }
        try? stdinPipe.fileHandleForWriting.close()
        refresh()
    }

    private func stop() {
        intendRunning = false
        if let proc = task, proc.isRunning {
            proc.terminate()
            task = nil
            refresh()
        } else {
            stopFolderSync { [weak self] in self?.refresh() }
        }
    }

    // After a folder or key change, relaunch only if a sync is running.
    private func reloadIfRunning() {
        if isRunning { startFromCacheOrPrompt() } else { refresh() }
    }

    @objc private func toggle() {
        if isRunning { stop() } else { promptAndStart() }
    }

    @objc private func restart() {
        promptAndStart()
    }

    // A wake relaunches the sync from the cached passphrase after Wi-Fi has had a moment to reassociate.
    @objc private func systemDidWake(_ note: Notification) {
        guard intendRunning else { return }
        stopFolderSync { [weak self] in
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                guard let self, self.intendRunning, !self.ownChild, self.cache.unlocked else { return }
                self.spawn(readConfig())
            }
        }
    }

    @objc private func openLog() {
        NSWorkspace.shared.open(logURL)
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
            cache.clear()
            reloadIfRunning()
        }
    }

    @objc private func clearKey() {
        var cfg = readConfig()
        cfg.key = ""
        writeConfig(cfg)
        cache.clear()
        reloadIfRunning()
    }

    // Quitting stops this agent's own sync (applicationWillTerminate), never one started elsewhere.
    @objc private func quit() {
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
