//! `secsec`, the single binary: the blind server and every client command (`secsec-Design.md` §7, §10, §11, §12). Usage: README.md.

#![allow(missing_docs)] // a binary crate has no public API

use clap::{Args, Parser, Subcommand};
use secsec_client::history::{LogEntry, PathVersion};
use secsec_client::pair;
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{
    data_keyring_remote, init_repo_remote, open_repo_remote, revoke_preview, roster_grew,
    rotate_repo_remote, RepoError, Revoke, RosterAnchor,
};
use secsec_client::sync::{sync_once, SyncInput, SyncKind, SyncOutcome};
use secsec_client::{
    fetch_head, fetch_verified_head, load_frontier, save_frontier, write_private_atomic,
    ClientError, FrontierLoad,
};
use secsec_engine::MergeError;
use secsec_kdf::MasterKey;
use secsec_proto::server::{Limits, WindowCounter};
use secsec_roster::State;
use secsec_server::{serve::serve_connection, Server};
use secsec_sig::{DeviceKey, SigError};
use secsec_snapshot::SnapshotMemo;
use secsec_store::Store;
use secsec_sync::rollback::SyncFrontier;
use secsec_sync::HeadError;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{
    client_config_tofu, client_config_tuned, server_config_tuned, Tuning,
};
use secsec_transport::HostPin;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroizing;

type CliResult<T> = Result<T, Box<dyn Error>>;

/// The data key ring a cold start peels (§8.2).
type Keyring = BTreeMap<u32, MasterKey>;

/// The port a bare `host` means (§19, udp/8899), and the default listen port.
const DEFAULT_PORT: u16 = 8899;
/// Pairing-mailbox polls (500 ms apart) the inviting device waits: the invite's lifetime.
const PAIR_HOST_ROUNDS: u32 = 1200;
/// Pairing-mailbox polls the joining device waits.
const PAIR_JOIN_ROUNDS: u32 = 240;
/// Pause between reconnect attempts after the connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Interactive passphrase attempts.
const MAX_PASSPHRASE_TRIES: usize = 3;
/// The one ref every folder syncs (one repository holds one tree).
const REF: &str = "main";
/// What `--version` prints: the release tag a release build is stamped with (`SECSEC_RELEASE`), else the crate version.
const RELEASE: &str = match option_env!("SECSEC_RELEASE") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(
    name = "secsec",
    version = RELEASE,
    about = "Zero-knowledge end-to-end-encrypted file sync"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct KeyArgs {
    /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,
    /// Read the key passphrase from stdin (a pipe, never argv) instead of prompting.
    #[arg(long)]
    passphrase_stdin: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the blind sync server; every connection is gated on ~/.ssh/authorized_keys.
    Serve {
        /// Directory for the encrypted repository and the host key (default: current directory).
        dir: Option<PathBuf>,
        /// UDP port to listen on (default: listen_port in secsec.config).
        #[arg(long)]
        port: Option<u16>,
    },
    /// Keep a folder in continuous two-way sync with its repository.
    Sync {
        /// The folder to sync (default: current directory).
        dir: Option<PathBuf>,
        /// Server host[:port], needed the first time a folder is linked.
        #[arg(long)]
        server: Option<String>,
        /// The server's host pin (`secsec hostpin --serve <dir>` there); without it the first connection trusts on first use.
        #[arg(long, value_name = "HOST_PIN")]
        pin: Option<String>,
        /// Join an existing repository with a one-time invite code; without a value, prompt for it.
        #[arg(long, value_name = "CODE", num_args = 0..=1, default_missing_value = "")]
        invite: Option<String>,
        /// Sync once and exit instead of watching for changes.
        #[arg(long)]
        once: bool,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Stop the sync running for a folder (default: the synced folder you are in).
    Stop {
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
    },
    /// Show whether a folder's sync is running and how it last went, as key=value lines.
    Status {
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
    },
    /// On an enrolled device: print a one-time invite code and pair a new device over the wire.
    Invite {
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// List the devices enrolled in the repository, with their SSH key fingerprints.
    Devices {
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Print a server host pin: the one a folder pinned, or with --serve the server's own.
    Hostpin {
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
        /// A serve directory: print its host pin, creating the host key if it does not exist yet.
        #[arg(long, value_name = "DIR", conflicts_with = "dir")]
        serve: Option<PathBuf>,
    },
    /// Show the repository's change log; with a path, that file or folder's versions.
    Log {
        /// A file or folder, relative to the current directory inside the synced folder.
        path: Option<String>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Write an earlier version of a file or folder into the synced folder; the running sync propagates it.
    Restore {
        /// A file or folder, relative to the current directory inside the synced folder.
        path: String,
        /// A commit-id prefix from `secsec log <path>`; omit for the previous version.
        version: Option<String>,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Revoke a device and the devices it granted since this one last checked, rotating the key away from them.
    Revoke {
        /// The device id, or a unique prefix of it, from `secsec devices`.
        device: String,
        /// A synced folder, or a path inside one.
        dir: Option<PathBuf>,
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Remove secsec's own state for a folder and/or serve directory; your files and SSH keys stay.
    Reset {
        /// The synced folder and/or serve directory (default: current directory).
        dir: Option<PathBuf>,
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

// ---- small helpers ----

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> CliResult<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.is_ascii() {
        return Err("expected 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "invalid hex")?;
    }
    Ok(out)
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn random<const N: usize>() -> CliResult<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b)?;
    Ok(b)
}

fn home() -> CliResult<PathBuf> {
    std::env::home_dir()
        .filter(|p| p.is_absolute())
        .ok_or_else(|| "cannot determine the home directory".into())
}

/// The client root: `$XDG_CONFIG_HOME/secsec` when that is absolute, else `~/.config/secsec`; the desktop UIs use the same.
fn config_root() -> CliResult<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => home()?.join(".config"),
    };
    Ok(base.join("secsec"))
}

/// Create `dir` and its parents, and make `dir` owner-only (0700 on unix).
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

fn not_found(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
}

/// Ask a yes/no question on the terminal; anything but yes is no.
fn confirm(question: &str) -> CliResult<bool> {
    use std::io::Write;
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

/// Resolves on Ctrl-C (or never, where signals are unavailable).
async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Resolves on Ctrl-C, or SIGTERM on unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                () = ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    ctrl_c().await;
}

/// Sleep until `deadline`; `None` (beyond the clock's range) never wakes.
async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

fn deadline_after(d: Duration) -> Option<tokio::time::Instant> {
    tokio::time::Instant::now().checked_add(d)
}

// ---- secsec.config (§19) ----

/// Operator-tunable settings from `<config root>/secsec.config`; out-of-range values are clamped on load.
struct Config {
    retention_keep_versions: usize,
    watch_debounce_ms: u64,
    poll_interval_secs: u64,
    quic_idle_secs: u64,
    quic_keepalive_secs: u64,
    listen_port: u16,
    storage_cap_gib: u64,
    write_rate_mb_s: u64,
    read_rate_mb_s: u64,
    conn_rate_per_ip: u64,
    max_conns_per_key: u64,
    max_connections: u64,
    staging_ttl_hours: u64,
    reclaim_tick_minutes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            retention_keep_versions: 8,
            watch_debounce_ms: 1000,
            poll_interval_secs: 15,
            quic_idle_secs: 30,
            quic_keepalive_secs: 10,
            listen_port: DEFAULT_PORT,
            storage_cap_gib: 0,
            write_rate_mb_s: 100,
            read_rate_mb_s: 200,
            conn_rate_per_ip: 10,
            max_conns_per_key: 3,
            max_connections: 256,
            staging_ttl_hours: 24,
            reclaim_tick_minutes: 60,
        }
    }
}

/// The default `secsec.config`, written on first use when none exists.
const CONFIG_TEMPLATE: &str = "\
# secsec.config: operator-tunable settings, clamped to their ranges on load; everything else is compiled in.

[client]
retention_keep_versions = 8     # versions kept per file (0 = keep every version)
watch_debounce_ms       = 1000  # quiet time that ends a burst of edits (min 100)
poll_interval_secs      = 15    # periodic re-sync, and the longest a burst of edits waits (min 5)
quic_idle_secs          = 30    # connection idle timeout, also the server's handshake deadline (min 5)
quic_keepalive_secs     = 10    # keepalive interval (min 1, kept below quic_idle_secs)

[server]
listen_port          = 8899  # UDP port (1-65535)
storage_cap_gib      = 0     # per-key new-write cap per server run, GiB (0 = unlimited)
write_rate_mb_s      = 100   # per-key sustained write rate, MB/s (min 1)
read_rate_mb_s       = 200   # per-key sustained read rate, MB/s (min 1)
conn_rate_per_ip     = 10    # new connections per second per source IP (min 1)
max_conns_per_key    = 3     # concurrent connections per device key (min 1)
max_connections      = 256   # concurrent connections server-wide, handshakes in flight included (min 1)
staging_ttl_hours    = 24    # idle hours before an abandoned upload's staging is reclaimed (min 1)
reclaim_tick_minutes = 60    # how often the server sweeps idle staging (min 1)
";

impl Config {
    /// Load the config; only a missing file is replaced by the template, any other read error is reported.
    fn load() -> CliResult<Config> {
        let path = config_root()?.join("secsec.config");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if not_found(&e) => {
                if let Some(parent) = path.parent() {
                    create_dir_private(parent)?;
                }
                write_private_atomic(&path, CONFIG_TEMPLATE.as_bytes())?;
                CONFIG_TEMPLATE.to_string()
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display()).into()),
        };
        let mut cfg = Config::default();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('[') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                cfg.apply(k.trim(), v.trim());
            }
        }
        cfg.clamp();
        Ok(cfg)
    }

    /// Set one field; an unknown key or an unparseable value leaves the default.
    fn apply(&mut self, key: &str, val: &str) {
        match key {
            "retention_keep_versions" => set(&mut self.retention_keep_versions, val),
            "watch_debounce_ms" => set(&mut self.watch_debounce_ms, val),
            "poll_interval_secs" => set(&mut self.poll_interval_secs, val),
            "quic_idle_secs" => set(&mut self.quic_idle_secs, val),
            "quic_keepalive_secs" => set(&mut self.quic_keepalive_secs, val),
            "listen_port" => set(&mut self.listen_port, val),
            "storage_cap_gib" => set(&mut self.storage_cap_gib, val),
            "write_rate_mb_s" => set(&mut self.write_rate_mb_s, val),
            "read_rate_mb_s" => set(&mut self.read_rate_mb_s, val),
            "conn_rate_per_ip" => set(&mut self.conn_rate_per_ip, val),
            "max_conns_per_key" => set(&mut self.max_conns_per_key, val),
            "max_connections" => set(&mut self.max_connections, val),
            "staging_ttl_hours" => set(&mut self.staging_ttl_hours, val),
            "reclaim_tick_minutes" => set(&mut self.reclaim_tick_minutes, val),
            _ => {}
        }
    }

    /// Clamp to the documented minimums; the idle timeout also stays within what QUIC can express.
    fn clamp(&mut self) {
        self.watch_debounce_ms = self.watch_debounce_ms.max(100);
        self.poll_interval_secs = self.poll_interval_secs.max(5);
        self.quic_idle_secs = self.quic_idle_secs.clamp(5, Tuning::MAX_IDLE_SECS);
        self.quic_keepalive_secs = self
            .quic_keepalive_secs
            .clamp(1, self.quic_idle_secs.saturating_sub(1).max(1));
        if self.listen_port == 0 {
            self.listen_port = DEFAULT_PORT;
        }
        self.write_rate_mb_s = self.write_rate_mb_s.max(1);
        self.read_rate_mb_s = self.read_rate_mb_s.max(1);
        self.conn_rate_per_ip = self.conn_rate_per_ip.max(1);
        self.max_conns_per_key = self.max_conns_per_key.max(1);
        self.max_connections = self.max_connections.max(1);
        self.staging_ttl_hours = self.staging_ttl_hours.max(1);
        self.reclaim_tick_minutes = self.reclaim_tick_minutes.max(1);
    }

    fn tuning(&self) -> Tuning {
        Tuning {
            idle_secs: self.quic_idle_secs,
            keepalive_secs: self.quic_keepalive_secs,
        }
    }

    fn idle(&self) -> Duration {
        Duration::from_secs(self.quic_idle_secs)
    }

    /// Server limits: rates in decimal MB/s to bytes/s, the cap in GiB to bytes (0 = unlimited).
    fn limits(&self) -> Limits {
        Limits {
            write_rate: self.write_rate_mb_s.saturating_mul(1_000_000),
            read_rate: self.read_rate_mb_s.saturating_mul(1_000_000),
            conn_rate_per_sec: self.conn_rate_per_ip,
            max_conns_per_key: self.max_conns_per_key,
            max_connections: self.max_connections,
            storage_cap: self.storage_cap_gib.saturating_mul(1024 * 1024 * 1024),
        }
    }
}

fn set<T: std::str::FromStr>(field: &mut T, val: &str) {
    if let Ok(v) = val.parse() {
        *field = v;
    }
}

// ---- device key ----

/// Refuse a private key that other users can read, as ssh does.
fn check_key_permissions(path: &Path) -> CliResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("cannot read device key {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "permissions {:o} on {} are too open: the private key must be accessible by its owner only (chmod 600)",
                mode & 0o777,
                path.display()
            )
            .into());
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Load this device's SSH key, decrypting a passphrase-protected one in memory only.
fn load_device(k: &KeyArgs) -> CliResult<DeviceKey> {
    let path = match &k.key {
        Some(p) => p.clone(),
        None => home()?.join(".ssh").join("id_ed25519"),
    };
    check_key_permissions(&path)?;
    let pem = Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read device key {}: {e}", path.display()))?,
    );
    match DeviceKey::from_openssh(&pem) {
        Ok(device) => Ok(device),
        Err(SigError::Encrypted) if k.passphrase_stdin => decrypt_stdin(&pem),
        Err(SigError::Encrypted) => decrypt_prompt(&pem, &path),
        Err(e) => Err(format!("cannot load device key {}: {e}", path.display()).into()),
    }
}

/// Prompt for the passphrase without echo; each typed passphrase is zeroized after its try.
fn decrypt_prompt(pem: &str, path: &Path) -> CliResult<DeviceKey> {
    for attempt in 1..=MAX_PASSPHRASE_TRIES {
        let passphrase = Zeroizing::new(rpassword::prompt_password(format!(
            "passphrase for {}: ",
            path.display()
        ))?);
        match DeviceKey::from_openssh_passphrase(pem, &passphrase) {
            Ok(device) => return Ok(device),
            Err(SigError::BadPassphrase) if attempt < MAX_PASSPHRASE_TRIES => {
                eprintln!("wrong passphrase, try again");
            }
            Err(SigError::BadPassphrase) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err("could not decrypt the device key: wrong passphrase".into())
}

/// Decrypt with one passphrase read from stdin, the first line without its line ending.
fn decrypt_stdin(pem: &str) -> CliResult<DeviceKey> {
    use std::io::BufRead;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    let passphrase = Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string());
    match DeviceKey::from_openssh_passphrase(pem, &passphrase) {
        Ok(device) => Ok(device),
        Err(SigError::BadPassphrase) => Err("wrong passphrase (read from stdin)".into()),
        Err(e) => Err(e.into()),
    }
}

// ---- folder state ----

/// A folder's out-of-tree state directory, named by `BLAKE3` of its canonical path.
fn state_path(canonical: &Path) -> CliResult<PathBuf> {
    let name = hex(blake3::hash(canonical.to_string_lossy().as_bytes()).as_bytes());
    Ok(config_root()?.join("folders").join(name))
}

/// A folder's link to its repository: server, pinned host id, RFP, and the §8.1 anti-rollback anchor.
struct Link {
    server: String,
    host_id: [u8; 32],
    rfp: [u8; 32],
    anchor: Option<RosterAnchor>,
}

fn read_link(sdir: &Path) -> CliResult<Option<Link>> {
    let path = sdir.join("link");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let fields: BTreeMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    let field = |k: &str| {
        fields
            .get(k)
            .copied()
            .ok_or_else(|| format!("{} lacks `{k}`", path.display()))
    };
    let anchor = match (fields.get("roster_seq"), fields.get("roster_tip")) {
        (Some(seq), Some(tip)) => Some(RosterAnchor {
            max_seq: seq.parse()?,
            tip_hash: parse_hex32(tip)?,
        }),
        _ => None,
    };
    Ok(Some(Link {
        server: field("server")?.to_string(),
        host_id: parse_hex32(field("host_id")?)?,
        rfp: parse_hex32(field("rfp")?)?,
        anchor,
    }))
}

fn write_link(sdir: &Path, l: &Link) -> CliResult<()> {
    let mut body = format!(
        "server={}\nhost_id={}\nrfp={}\n",
        l.server,
        hex(&l.host_id),
        hex(&l.rfp)
    );
    if let Some(a) = &l.anchor {
        body.push_str(&format!(
            "roster_seq={}\nroster_tip={}\n",
            a.max_seq,
            hex(&a.tip_hash)
        ));
    }
    write_private_atomic(&sdir.join("link"), body.as_bytes())?;
    Ok(())
}

/// Take a blocking exclusive lock on `path` (created if absent), released when the handle drops.
fn lock_file(path: &Path) -> CliResult<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    f.lock()?;
    Ok(f)
}

/// Record a newer anchor in the link of `rfp`'s folder; the stored anchor never moves backwards (§8.1).
fn persist_anchor(sdir: &Path, rfp: &[u8; 32], anchor: RosterAnchor) -> CliResult<()> {
    let _guard = lock_file(&sdir.join("link.lock"))?;
    let Some(mut link) = read_link(sdir)? else {
        return Ok(());
    };
    if link.rfp != *rfp || link.anchor.is_some_and(|a| a.max_seq >= anchor.max_seq) {
        return Ok(());
    }
    link.anchor = Some(anchor);
    write_link(sdir, &link)
}

/// Find the synced folder containing `start`: its canonical root, state directory, and link.
fn find_linked(start: &Path) -> CliResult<(PathBuf, PathBuf, Link)> {
    let canonical = std::fs::canonicalize(start)
        .map_err(|e| format!("cannot resolve {}: {e}", start.display()))?;
    for dir in canonical.ancestors() {
        let sdir = state_path(dir)?;
        if let Some(link) = read_link(&sdir)? {
            return Ok((dir.to_path_buf(), sdir, link));
        }
    }
    Err(format!(
        "{} is not inside a synced folder (link one with `secsec sync <folder> --server <host>`)",
        canonical.display()
    )
    .into())
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A folder's sync lock, held for the sync's lifetime and naming its pid.
struct FolderLock(#[allow(dead_code)] std::fs::File);

impl FolderLock {
    fn acquire(sdir: &Path, dir: &Path) -> CliResult<Self> {
        use std::io::Write;
        let path = sdir.join("lock");
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        match f.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                let who = read_pid(&path).map_or_else(String::new, |p| format!(" (pid {p})"));
                return Err(format!(
                    "{} is already being synced{who}; stop it with `secsec stop {}`",
                    dir.display(),
                    dir.display()
                )
                .into());
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        f.set_len(0)?;
        writeln!(f, "{}", std::process::id())?;
        f.sync_all()?;
        Ok(Self(f))
    }
}

/// `Some(pid)` while a sync holds the folder's lock (the pid when readable), `None` when none does.
fn lock_holder(sdir: &Path) -> CliResult<Option<Option<u32>>> {
    let path = sdir.join("lock");
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if not_found(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match f.try_lock() {
        Ok(()) => Ok(None),
        Err(std::fs::TryLockError::WouldBlock) => Ok(Some(read_pid(&path))),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// What a running sync last reported, for `secsec status` and the desktop UIs.
#[derive(Default)]
struct Status {
    state: &'static str,
    last_sync: u64,
    result: &'static str,
    conflicts: usize,
    skipped: usize,
    message: String,
}

impl Status {
    fn write(&self, sdir: &Path) {
        let message: String = self
            .message
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let body = format!(
            "pid={}\nstate={}\nlast_sync={}\nlast_result={}\nconflicts={}\nskipped={}\nmessage={message}\n",
            std::process::id(),
            self.state,
            self.last_sync,
            self.result,
            self.conflicts,
            self.skipped
        );
        if let Err(e) = write_private_atomic(&sdir.join("status"), body.as_bytes()) {
            eprintln!("warning: cannot write the status file: {e}");
        }
    }

    fn set(&mut self, sdir: &Path, state: &'static str, message: impl Into<String>) {
        self.state = state;
        self.message = message.into();
        self.write(sdir);
    }
}

fn kind_word(kind: SyncKind) -> &'static str {
    match kind {
        SyncKind::UpToDate => "uptodate",
        SyncKind::Published => "published",
        SyncKind::Cloned => "cloned",
        SyncKind::Pulled => "pulled",
        SyncKind::Pushed => "pushed",
        SyncKind::Merged => "merged",
    }
}

// ---- connections ----

/// Resolve `host[:port]`, IPv6 literals included (`[::1]:8899`, `::1`, `[::1]`); the port defaults to 8899.
fn resolve_server(s: &str) -> CliResult<SocketAddr> {
    let s = s.trim();
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, DEFAULT_PORT).into());
    }
    if let Some(ip) = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .and_then(|b| b.parse::<IpAddr>().ok())
    {
        return Ok((ip, DEFAULT_PORT).into());
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (
            h,
            p.parse::<u16>()
                .map_err(|_| format!("invalid port in '{s}'"))?,
        ),
        _ => (s, DEFAULT_PORT),
    };
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("cannot resolve server address '{s}'").into())
}

/// Connect to `addr`, pinning `pinned` or capturing the host id on first contact (TOFU, §11).
async fn connect(
    addr: SocketAddr,
    pinned: Option<[u8; 32]>,
    tuning: Tuning,
) -> CliResult<(quinn::Endpoint, quinn::Connection, [u8; 32])> {
    let bind: SocketAddr = if addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut ep = quinn::Endpoint::client(bind)?;
    match pinned {
        Some(h) => {
            ep.set_default_client_config(client_config_tuned(HostPin::from_host_id(h), tuning)?);
            let conn = ep.connect(addr, "secsec.invalid")?.await?;
            Ok((ep, conn, h))
        }
        None => {
            let (cfg, captured) = client_config_tofu(tuning)?;
            ep.set_default_client_config(cfg);
            let conn = ep.connect(addr, "secsec.invalid")?.await?;
            let host_id = (*captured.lock().map_err(|_| "TOFU capture poisoned")?)
                .ok_or("the server presented no host key")?;
            Ok((ep, conn, host_id))
        }
    }
}

/// Connect to a linked folder's pinned server and run the §11 handshake; returns the session transcript.
async fn connect_linked(
    link: &Link,
    device: &DeviceKey,
    tuning: Tuning,
) -> CliResult<(quinn::Endpoint, quinn::Connection, [u8; 32])> {
    let addr = resolve_server(&link.server)?;
    let (ep, conn, host_id) = connect(addr, Some(link.host_id), tuning).await?;
    let t = client_handshake(&conn, device, host_id, random()?)
        .await?
        .transcript;
    Ok((ep, conn, t))
}

// ---- server ----

/// Load the host key from `dir`, or create it; a half-present pair is an error, never silently replaced.
fn load_or_generate_hostkey(dir: &Path) -> CliResult<(Vec<u8>, Vec<u8>)> {
    let cert_path = dir.join("hostkey.crt");
    let key_path = dir.join("hostkey.key");
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok((std::fs::read(cert_path)?, std::fs::read(key_path)?))
        }
        (false, false) => {
            let ck = rcgen::generate_simple_self_signed(vec!["secsec.invalid".to_string()])?;
            let (cert, key) = (
                ck.cert.der().to_vec(),
                Zeroizing::new(ck.key_pair.serialize_der()),
            );
            create_dir_private(dir)?;
            write_private_atomic(&key_path, &key)?;
            write_private_atomic(&cert_path, &cert)?;
            Ok((cert, key.to_vec()))
        }
        _ => Err(format!(
            "{} holds only half of the host key; restore the missing file or run `secsec reset`",
            dir.display()
        )
        .into()),
    }
}

/// A UDP socket on `port`: dual-stack `[::]` where IPv6 exists, else IPv4 only.
fn bind_udp(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let v6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).and_then(|s| {
        s.set_only_v6(false)?;
        s.bind(&SockAddr::from(SocketAddr::from((
            Ipv6Addr::UNSPECIFIED,
            port,
        ))))?;
        Ok(s)
    });
    let socket = match v6 {
        Ok(s) => s,
        Err(_) => {
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.bind(&SockAddr::from(SocketAddr::from((
                Ipv4Addr::UNSPECIFIED,
                port,
            ))))?;
            s
        }
    };
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

async fn run_serve(dir: PathBuf, port: Option<u16>) -> CliResult<()> {
    let cfg = Config::load()?;
    let port = port.unwrap_or(cfg.listen_port);
    create_dir_private(&dir)?;
    let auth_path = home()?.join(".ssh").join("authorized_keys");
    let body = std::fs::read_to_string(&auth_path).map_err(|e| {
        format!(
            "{} is required: secsec serve admits only its keys ({e})",
            auth_path.display()
        )
    })?;
    let authorized = secsec_server::parse_authorized_keys(&body);
    if authorized.is_empty() {
        return Err(format!(
            "{} has no Ed25519 keys; add each device's public key (its ~/.ssh/id_ed25519.pub)",
            auth_path.display()
        )
        .into());
    }

    let (cert, key) = load_or_generate_hostkey(&dir.join("hostkey"))?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    let store_path = dir.join("repo.secsec");
    let mut store = Store::open(&store_path).map_err(|e| {
        format!(
            "cannot open {} ({e}); is another secsec serve using it?",
            store_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600))?;
    }
    // Compact while nothing else holds the store, so pruned pages shrink the file (§15).
    let before = std::fs::metadata(&store_path).map_or(0, |m| m.len());
    match store.compact() {
        Ok(true) => {
            let after = std::fs::metadata(&store_path).map_or(before, |m| m.len());
            println!(
                "compacted {} ({before} to {after} bytes)",
                store_path.display()
            );
        }
        Ok(false) => {}
        Err(e) => eprintln!("repository compaction skipped: {e}"),
    }
    let server = Arc::new(
        Server::new(store)
            .with_limits(cfg.limits())
            .with_authorized_file(auth_path.clone()),
    );

    // Abandoned staging and idle rate-limit state are reclaimed on a timer, since an idle accept loop never runs.
    {
        let server = server.clone();
        let ttl = cfg.staging_ttl_hours.saturating_mul(3600);
        let tick = Duration::from_secs(cfg.reclaim_tick_minutes.saturating_mul(60));
        tokio::spawn(async move {
            loop {
                sleep_until(deadline_after(tick)).await;
                if let Err(e) = server.reclaim(unix_secs(), ttl) {
                    eprintln!("staging reclaim failed: {e}");
                }
            }
        });
    }

    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config_tuned(&cert, &key, cfg.tuning())?),
        bind_udp(port)?,
        Arc::new(quinn::TokioRuntime),
    )?;
    println!(
        "secsec serve: store {}, host pin {}",
        store_path.display(),
        hex(&host_id)
    );
    println!(
        "authorized_keys: {} ({} key(s)), listening on udp {}",
        auth_path.display(),
        authorized.len(),
        endpoint.local_addr()?
    );

    // Per-source-IP new-connection rate (§19); pruned at most once per window so idle IPs do not accumulate.
    let conn_rate = server.conn_rate_per_sec();
    let mut ip_rate: HashMap<IpAddr, WindowCounter> = HashMap::new();
    let mut last_prune = 0u64;
    let idle = cfg.idle();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => match i {
                Some(i) => i,
                None => break,
            },
            () = &mut shutdown => break,
        };
        // A stateless Retry validates the source address first: anti-amplification, and no spoofed rate budget.
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        let now = unix_secs();
        let ip = incoming.remote_address().ip();
        if now.saturating_sub(last_prune) >= 1 {
            ip_rate.retain(|_, c| c.count(now) > 0);
            last_prune = now;
        }
        let allowed = ip_rate
            .entry(ip)
            .or_insert_with(|| WindowCounter::new(1, conn_rate))
            .try_record(now);
        if !allowed {
            incoming.refuse();
            continue;
        }
        // The server-wide cap (§19) holds this slot from before the handshake until the task ends.
        let Some(admission) = server.admit() else {
            incoming.refuse();
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            let _admission = admission;
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = serve_connection(&conn, server, host_id, idle, unix_secs).await
                    {
                        eprintln!("connection closed: {e}");
                    }
                }
                Err(e) => eprintln!("accept failed: {e}"),
            }
        });
    }
    println!("shutting down");
    endpoint.close(0u32.into(), b"server shutting down");
    endpoint.wait_idle().await;
    Ok(())
}

// ---- sync ----

/// Where one folder's sync keeps its state files.
struct Paths {
    frontier: PathBuf,
    base: PathBuf,
    push_id: PathBuf,
    objects: PathBuf,
}

impl Paths {
    fn new(sdir: &Path) -> Self {
        Self {
            frontier: sdir.join("frontier"),
            base: sdir.join("base"),
            push_id: sdir.join("push_id"),
            objects: sdir.join("objects.secsec"),
        }
    }
}

fn read_base(path: &Path) -> CliResult<Option<[u8; 32]>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(parse_hex32(&s)?)),
        Err(e) if not_found(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Refuse a folder that contains secsec's own state directory: it would sync itself.
fn refuse_state_inside(dir: &Path) -> CliResult<()> {
    let root = config_root()?;
    create_dir_private(&root)?;
    let root = std::fs::canonicalize(&root)?;
    if root.starts_with(dir) {
        return Err(format!(
            "{} contains secsec's state directory {}; sync another folder, or set XDG_CONFIG_HOME outside it",
            dir.display(),
            root.display()
        )
        .into());
    }
    Ok(())
}

/// What `secsec sync` was asked to do.
struct SyncArgs {
    server: Option<String>,
    pin: Option<String>,
    invite: Option<String>,
    once: bool,
    key: KeyArgs,
}

async fn run_sync(dir: PathBuf, args: SyncArgs) -> CliResult<()> {
    std::fs::create_dir_all(&dir)?;
    let dir = std::fs::canonicalize(&dir)?;
    refuse_state_inside(&dir)?;
    let sdir = state_path(&dir)?;
    create_dir_private(&sdir)?;
    let _lock = FolderLock::acquire(&sdir, &dir)?;
    let mut status = Status::default();
    status.set(&sdir, "starting", "starting");
    let result = sync_session(&dir, &sdir, args, &mut status).await;
    match &result {
        Ok(()) => status.set(&sdir, "stopped", "stopped"),
        Err(e) => status.set(&sdir, "stopped", e.to_string()),
    }
    result
}

/// Open the repository after a roster change: refold against `anchor` and re-peel the key ring; the caller records the new anchor.
async fn refold(
    rem: &QuicRemote<'_>,
    device: &DeviceKey,
    rfp: &[u8; 32],
    anchor: RosterAnchor,
) -> Result<(State, RosterAnchor, Keyring), RepoError> {
    let (mk, st, a) = open_repo_remote(rem, device, rfp, Some(anchor)).await?;
    let keyring = data_keyring_remote(rem, &mk, &st).await?;
    Ok((st, a, keyring))
}

/// Print what a sync did and update the status the UIs read.
fn report(out: &SyncOutcome, first: bool, last_skipped: &mut Vec<String>, status: &mut Status) {
    if first || out.kind != SyncKind::UpToDate {
        println!("sync: {}", kind_word(out.kind));
    }
    if !out.conflicts.is_empty() {
        eprintln!(
            "{} path(s) changed on both sides; both versions are kept (the other as a .conflict- copy):",
            out.conflicts.len()
        );
        for p in &out.conflicts {
            eprintln!("  {p}");
        }
    }
    if out.base_missing {
        eprintln!(
            "warning: the merge base is no longer on the server, so files deleted on one side may reappear"
        );
    }
    if out.skipped != *last_skipped && !out.skipped.is_empty() {
        eprintln!(
            "warning: {} path(s) cannot sync here and keep their last synced version:",
            out.skipped.len()
        );
        for p in &out.skipped {
            eprintln!("  {p}");
        }
    }
    last_skipped.clone_from(&out.skipped);
    status.last_sync = unix_secs();
    status.result = kind_word(out.kind);
    status.conflicts = out.conflicts.len();
    status.skipped = out.skipped.len();
}

/// Wait for the next watcher event; a closed watcher leaves only the poll timer.
async fn next_change(rx: &mut Option<UnboundedReceiver<()>>) {
    if let Some(r) = rx.as_mut() {
        if r.recv().await.is_some() {
            while r.try_recv().is_ok() {}
            return;
        }
        *rx = None;
    }
    std::future::pending::<()>().await;
}

#[allow(clippy::too_many_lines)]
async fn sync_session(
    dir: &Path,
    sdir: &Path,
    args: SyncArgs,
    status: &mut Status,
) -> CliResult<()> {
    let SyncArgs {
        server: server_opt,
        pin,
        invite: invite_opt,
        once,
        key,
    } = args;
    let device = load_device(&key)?;
    let cfg = Config::load()?;
    let link = read_link(sdir)?;
    let server_str = server_opt
        .or_else(|| link.as_ref().map(|l| l.server.clone()))
        .ok_or("no server for this folder: pass --server host[:port] the first time")?;
    let addr = resolve_server(&server_str)?;
    let expected = pin.as_deref().map(parse_hex32).transpose()?;
    let pinned = match (link.as_ref().map(|l| l.host_id), expected) {
        (Some(have), Some(want)) if have != want => {
            return Err(format!(
                "{} is pinned to host {}, not the --pin given; `secsec reset` it to re-pin",
                dir.display(),
                hex(&have)
            )
            .into())
        }
        (have, want) => have.or(want),
    };
    status.set(sdir, "connecting", format!("connecting to {server_str}"));
    let (mut endpoint, mut conn, host_id) = connect(addr, pinned, cfg.tuning()).await?;
    if pinned.is_none() {
        println!(
            "server host pin (compare with `secsec hostpin --serve <dir>` on the server): {}",
            hex(&host_id)
        );
    }
    let mut transcript = client_handshake(&conn, &device, host_id, random()?)
        .await?
        .transcript;

    let rfp = {
        let rem = QuicRemote::new(&conn, transcript, &device);
        match invite_opt {
            Some(code) => {
                let code = if code.is_empty() {
                    Zeroizing::new(rpassword::prompt_password("invite code: ")?)
                } else {
                    Zeroizing::new(code)
                };
                let code = pair::decode_code(&code)?;
                println!("pairing with an enrolled device...");
                pair::run_join(&rem, &device, &code, &host_id, PAIR_JOIN_ROUNDS).await?
            }
            None => match &link {
                Some(l) => l.rfp,
                None => match init_repo_remote(&rem, &device, unix_secs()).await {
                    Ok(rfp) => {
                        println!("created a new repository");
                        rfp
                    }
                    Err(RepoError::AlreadyEnrolled) => {
                        return Err(format!(
                            "this device is already enrolled in the repository on {server_str}, but {} is not linked to it: \
                             sync the folder you linked first, or link this one with an invite \
                             (`secsec invite` on an enrolled device, then `secsec sync {} --server {server_str} --invite`)",
                            dir.display(),
                            dir.display()
                        )
                        .into())
                    }
                    Err(RepoError::AlreadyInitialized) => {
                        return Err(format!(
                            "a repository already exists on {server_str}: join it with an invite from an enrolled device \
                             (`secsec invite` there, then `secsec sync {} --server {server_str} --invite`)",
                            dir.display()
                        )
                        .into())
                    }
                    Err(e) => return Err(e.into()),
                },
            },
        }
    };

    let paths = Paths::new(sdir);
    let was_linked = link.as_ref().is_some_and(|l| l.rfp == rfp);
    if link.is_some() && !was_linked {
        for p in [&paths.base, &paths.frontier, &paths.push_id, &paths.objects] {
            match std::fs::remove_file(p) {
                Ok(()) => {}
                Err(e) if not_found(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        eprintln!(
            "this folder was linked to another repository; its local sync state starts fresh"
        );
    }
    let prev = link
        .as_ref()
        .filter(|l| l.rfp == rfp)
        .and_then(|l| l.anchor);
    let (mk, mut st, mut anchor, mut keyring) = {
        let rem = QuicRemote::new(&conn, transcript, &device);
        let (mk, st, anchor) = open_repo_remote(&rem, &device, &rfp, prev).await?;
        let keyring = data_keyring_remote(&rem, &mk, &st).await?;
        (mk, st, anchor, keyring)
    };
    {
        let _guard = lock_file(&sdir.join("link.lock"))?;
        write_link(
            sdir,
            &Link {
                server: server_str.clone(),
                host_id,
                rfp,
                anchor: Some(anchor),
            },
        )?;
    }

    let mut store = Store::open(&paths.objects)?;
    let mut frontier = match load_frontier(&paths.frontier, &device) {
        Ok(FrontierLoad::Loaded(f)) => f,
        Ok(FrontierLoad::Absent) => {
            if was_linked {
                eprintln!(
                    "warning: this folder's sync state is missing, so this run is treated as a reinstall; \
                     rollback protection resumes once it reconverges (§8.5)"
                );
            }
            SyncFrontier::default()
        }
        Err(ClientError::FrontierLost(e)) => {
            eprintln!(
                "ALARM: this folder's sealed sync state does not open ({e}); treating this run as a reinstall (§8.5)"
            );
            SyncFrontier::default()
        }
        Err(e) => return Err(e.into()),
    };
    let mut base = read_base(&paths.base)?;
    let mut resume_push_id: Option<[u8; 16]> = std::fs::read(&paths.push_id)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok());

    // Once per session, while nothing else reads the cache: drop orphans, then reclaim their pages.
    if let Some(b) = base {
        match secsec_client::prune::local_sweep(&keyring, &store, &b) {
            Ok(n) if n > 0 => eprintln!("local sweep: dropped {n} unreachable object(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("local sweep skipped: {e}"),
        }
    }
    if let Err(e) = store.compact() {
        eprintln!("cache compaction skipped: {e}");
    }

    println!(
        "syncing {} (generation {}, {} member(s)) with {server_str}",
        dir.display(),
        mk.generation(),
        st.members.len()
    );
    drop(mk);

    let poll = Duration::from_secs(cfg.poll_interval_secs);
    let mut rx = None;
    if !once {
        let (tx, r) = tokio::sync::mpsc::unbounded_channel::<()>();
        rx = Some(r);
        let wdir = dir.to_path_buf();
        let debounce = Duration::from_millis(cfg.watch_debounce_ms);
        std::thread::spawn(move || {
            let watched = secsec_client::watcher::watch_dir(&wdir, debounce, poll, |err| {
                if let Some(e) = err {
                    eprintln!("{e}; rescanning");
                }
                tx.send(()).is_ok()
            });
            if let Err(e) = watched {
                eprintln!(
                    "warning: cannot watch {} ({e}); syncing every {}s instead",
                    wdir.display(),
                    poll.as_secs()
                );
            }
        });
        println!("watching {} (Ctrl-C to stop)", dir.display());
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut stopping = false;
    let mut next_poll = deadline_after(poll);
    let mut memo = SnapshotMemo::default();
    let mut first = true;
    let mut retry_now = false;
    let mut force_refold = false;
    let mut refolded_for_head = false;
    let mut prune_pending = cfg.retention_keep_versions > 0;
    let mut last_skipped: Vec<String> = Vec::new();
    let mut last_error: Option<String> = None;

    loop {
        let mut tick = false;
        if !first && !retry_now {
            if status.state != "error" && status.state != "alarm" {
                status.set(sdir, "idle", "up to date");
            }
            tokio::select! {
                () = next_change(&mut rx) => {}
                () = sleep_until(next_poll) => {
                    tick = true;
                    next_poll = deadline_after(poll);
                }
                () = &mut shutdown, if !stopping => stopping = true,
            }
            if stopping {
                break;
            }
        }
        retry_now = false;

        // A dropped connection is replaced, and verified with a real round trip before it is trusted.
        if let Some(reason) = conn.close_reason() {
            status.set(sdir, "connecting", format!("reconnecting to {server_str}"));
            eprintln!("connection lost ({reason}); reconnecting to {server_str}...");
            let fresh = async {
                let (ep, c, h) = connect(addr, Some(host_id), cfg.tuning()).await?;
                let t = client_handshake(&c, &device, h, random()?)
                    .await?
                    .transcript;
                fetch_head(&QuicRemote::new(&c, t, &device), &keyring, REF).await?;
                Ok::<_, Box<dyn Error>>((ep, c, t))
            };
            match fresh.await {
                Ok((ep, c, t)) => {
                    endpoint = ep;
                    conn = c;
                    transcript = t;
                    force_refold = true;
                }
                Err(e) => {
                    eprintln!("reconnect failed: {e}; retrying");
                    first = false;
                    retry_now = true;
                    tokio::select! {
                        () = tokio::time::sleep(RECONNECT_DELAY) => {}
                        () = &mut shutdown, if !stopping => stopping = true,
                    }
                    if stopping {
                        break;
                    }
                    continue;
                }
            }
        }
        let rem = QuicRemote::new(&conn, transcript, &device);

        // A cheap probe each tick; the full refold runs only when the sigchain moved.
        if tick || force_refold || frontier.roster_seq > anchor.max_seq {
            let grew = force_refold
                || frontier.roster_seq > anchor.max_seq
                || roster_grew(&rem, &anchor).await.unwrap_or(false);
            force_refold = false;
            if grew {
                match refold(&rem, &device, &rfp, anchor).await {
                    Ok((s, a, k)) => {
                        st = s;
                        anchor = a;
                        keyring = k;
                        if let Err(e) = persist_anchor(sdir, &rfp, a) {
                            eprintln!("warning: cannot record the roster anchor: {e}");
                        }
                    }
                    Err(RepoError::Rollback) => {
                        let msg = format!(
                            "ALARM: the repository on {server_str} no longer extends the sigchain this folder verified (§8.1): \
                             the server may have been rolled back or replaced. Syncing stopped."
                        );
                        status.set(sdir, "alarm", msg.clone());
                        return Err(msg.into());
                    }
                    Err(RepoError::NoKeyslot) => {
                        let msg = "this device is no longer a member of the repository (revoked?); syncing stopped";
                        status.set(sdir, "error", msg);
                        return Err(msg.into());
                    }
                    Err(e) => {
                        if conn.close_reason().is_none() {
                            eprintln!("roster refresh failed, keeping the last known roster: {e}");
                        }
                    }
                }
            }
        }

        let push_id = match resume_push_id.take() {
            Some(p) => p,
            None => random()?,
        };
        write_private_atomic(&paths.push_id, &push_id)?;
        status.set(sdir, "syncing", "syncing");
        let seal = |f: &SyncFrontier| save_frontier(&paths.frontier, f, &device);
        let input = SyncInput {
            store: &store,
            dir,
            keys: &keyring,
            device: &device,
            roster: &st,
            ref_name: REF,
            ts: unix_secs(),
            push_id: &push_id,
            seal: &seal,
        };
        // A shutdown request lets the running sync finish, so the folder is never left half-restored.
        let result = {
            let fut = sync_once(&rem, &input, &frontier, base, &mut memo);
            tokio::pin!(fut);
            loop {
                tokio::select! {
                    r = &mut fut => break r,
                    () = &mut shutdown, if !stopping => {
                        stopping = true;
                        status.set(sdir, "stopping", "finishing the current sync");
                    }
                }
            }
        };
        let _ = std::fs::remove_file(&paths.push_id);

        match result {
            Ok(out) => {
                // The base lands before the frontier: a frontier ahead of its base would reject its own history.
                if let Some(b) = out.base {
                    write_private_atomic(&paths.base, hex(&b).as_bytes())?;
                }
                save_frontier(&paths.frontier, &out.frontier, &device)?;
                report(&out, first, &mut last_skipped, status);
                status.set(sdir, "idle", format!("last sync: {}", kind_word(out.kind)));
                frontier = out.frontier;
                base = out.base;
                refolded_for_head = false;
                last_error = None;
                if prune_pending && (first || tick) {
                    match secsec_client::prune::prune_history(
                        &rem,
                        &store,
                        &keyring,
                        &st,
                        REF,
                        cfg.retention_keep_versions,
                    )
                    .await
                    {
                        Ok(true) => prune_pending = false,
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("history prune skipped: {e}");
                            prune_pending = false;
                        }
                    }
                }
            }
            // A concurrent writer won the ref: fetch its head and merge right away.
            Err(ClientError::CasConflict) => retry_now = true,
            // An unknown signer or generation means our roster is stale: refold once and retry.
            Err(
                ClientError::HeadNotMember | ClientError::Head(HeadError::UnknownGeneration(_)),
            ) if !refolded_for_head => {
                refolded_for_head = true;
                force_refold = true;
                retry_now = true;
            }
            Err(ClientError::Merge(MergeError::Rollback(r))) => {
                let msg = format!(
                    "ALARM: the server offered history older than this folder already accepted ({r:?}); nothing was applied"
                );
                eprintln!("{msg}");
                status.set(sdir, "alarm", msg.clone());
                last_error = Some(msg);
            }
            Err(e) => {
                if conn.close_reason().is_none() {
                    eprintln!("sync error: {e}");
                    status.set(sdir, "error", e.to_string());
                }
                last_error = Some(e.to_string());
            }
        }
        first = false;
        if stopping || (once && !retry_now) {
            break;
        }
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    match last_error {
        Some(e) if once => Err(e.into()),
        _ => Ok(()),
    }
}

// ---- stop / status ----

#[cfg(unix)]
fn send_signal(pid: u32, kill: bool) -> CliResult<()> {
    use rustix::process::{kill_process, Pid, Signal};
    let pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or("the lock file names an invalid pid")?;
    match kill_process(pid, if kill { Signal::KILL } else { Signal::TERM }) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(unix))]
fn send_signal(_pid: u32, _kill: bool) -> CliResult<()> {
    Err("`secsec stop` needs a unix signal; end the process from the task manager instead".into())
}

/// Wait until the folder lock is free: `true` once it is, `false` if `limit` passes first.
fn wait_unlocked(sdir: &Path, limit: Option<Duration>) -> CliResult<bool> {
    let path = sdir.join("lock");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(lock_file(&path).map(drop).map_err(|e| e.to_string()));
    });
    let got = match limit {
        Some(d) => match rx.recv_timeout(d) {
            Ok(r) => r,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return Ok(false),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("lock waiter died".into())
            }
        },
        None => rx.recv().map_err(|_| "lock waiter died")?,
    };
    got.map(|()| true).map_err(Into::into)
}

fn run_stop(start: PathBuf) -> CliResult<()> {
    let (root, sdir, _) = find_linked(&start)?;
    let Some(pid) = lock_holder(&sdir)? else {
        println!("no sync is running for {}", root.display());
        return Ok(());
    };
    let pid = pid.ok_or("a sync holds this folder's lock, but its pid is unreadable")?;
    send_signal(pid, false)?;
    // A clean stop finishes its current sync; one that outlives the idle timeout is stuck.
    let cfg = Config::load()?;
    if !wait_unlocked(&sdir, Some(cfg.idle()))? {
        eprintln!(
            "the sync (pid {pid}) did not stop within {}s; killing it",
            cfg.quic_idle_secs
        );
        send_signal(pid, true)?;
        wait_unlocked(&sdir, None)?;
    }
    println!("stopped the sync of {} (pid {pid})", root.display());
    Ok(())
}

fn run_status(start: PathBuf) -> CliResult<()> {
    let (root, sdir, link) = find_linked(&start)?;
    let running = lock_holder(&sdir)?;
    println!("folder={}", root.display());
    println!("server={}", link.server);
    println!("running={}", if running.is_some() { "yes" } else { "no" });
    let text = match std::fs::read_to_string(sdir.join("status")) {
        Ok(t) => t,
        Err(e) if not_found(&e) => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut state_seen = false;
    for line in text.lines() {
        if line.starts_with("pid=") && running.is_none() {
            continue;
        }
        if line.starts_with("state=") {
            state_seen = true;
            if running.is_none() {
                println!("state=stopped");
                continue;
            }
        }
        println!("{line}");
    }
    if !state_seen {
        println!(
            "state={}",
            if running.is_some() {
                "starting"
            } else {
                "stopped"
            }
        );
    }
    Ok(())
}

// ---- invite / devices / hostpin ----

async fn run_invite(start: PathBuf, key: KeyArgs) -> CliResult<()> {
    let (_root, sdir, link) = find_linked(&start)?;
    let device = load_device(&key)?;
    let cfg = Config::load()?;
    let (endpoint, conn, t) = connect_linked(&link, &device, cfg.tuning()).await?;
    let rem = QuicRemote::new(&conn, t, &device);
    let (_mk, _st, anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    persist_anchor(&sdir, &link.rfp, anchor)?;

    let (code, display) = pair::new_invite()?;
    println!("INVITE CODE: {display}");
    println!(
        "on the new device (add its public key to the server's authorized_keys first):\n  secsec sync <dir> --server {} --pin {} --invite",
        link.server,
        hex(&link.host_id)
    );
    println!("waiting for the device to pair (Ctrl-C to cancel)...");
    let (enrolled, anchor) = pair::run_host(
        &rem,
        &device,
        &link.rfp,
        Some(anchor),
        &link.host_id,
        &code,
        PAIR_HOST_ROUNDS,
        unix_secs(),
    )
    .await?;
    persist_anchor(&sdir, &link.rfp, anchor)?;
    println!("paired device {}", hex(&enrolled));
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

async fn run_devices(start: PathBuf, key: KeyArgs) -> CliResult<()> {
    let (_root, sdir, link) = find_linked(&start)?;
    let device = load_device(&key)?;
    let me = device.device_id()?;
    let cfg = Config::load()?;
    let (endpoint, conn, t) = connect_linked(&link, &device, cfg.tuning()).await?;
    let rem = QuicRemote::new(&conn, t, &device);
    let (_mk, st, anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    persist_anchor(&sdir, &link.rfp, anchor)?;
    println!("{} device(s) in this repository:", st.members.len());
    for (id, pubkey) in &st.members {
        let fp = pubkey
            .ssh_fingerprint()
            .unwrap_or_else(|_| "<unknown>".to_string());
        let mark = if *id == me { "  (this device)" } else { "" };
        println!("  {}  {fp}{mark}", &hex(id)[..12]);
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn run_hostpin(start: PathBuf, serve: Option<PathBuf>) -> CliResult<()> {
    if let Some(dir) = serve {
        create_dir_private(&dir)?;
        let (cert, _) = load_or_generate_hostkey(&dir.join("hostkey"))?;
        println!("{}", hex(&HostPin::from_cert(&cert)?.host_id()));
        return Ok(());
    }
    let (root, _sdir, link) = find_linked(&start)?;
    println!("folder:   {}", root.display());
    println!("server:   {}", link.server);
    println!("host pin: {}", hex(&link.host_id));
    println!("compare it out-of-band with `secsec hostpin --serve <dir>` on the server.");
    Ok(())
}

// ---- log / restore ----

/// `arg` as a repository path: taken relative to `cwd`, which must lie inside the synced `root`.
fn repo_path(root: &Path, cwd: &Path, arg: &str) -> CliResult<String> {
    let arg = Path::new(arg);
    let joined = if arg.is_absolute() {
        arg.to_path_buf()
    } else {
        cwd.join(arg)
    };
    let rel = joined.strip_prefix(root).map_err(|_| {
        format!(
            "{} is outside the synced folder {}",
            joined.display(),
            root.display()
        )
    })?;
    let mut parts: Vec<&str> = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(p) => parts.push(p.to_str().ok_or("the path is not valid UTF-8")?),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop().ok_or("the path leaves the synced folder")?;
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("the path leaves the synced folder".into())
            }
        }
    }
    Ok(parts.join("/"))
}

/// Human-friendly age of an advisory commit timestamp (§10: `ts` is a hint).
fn rel_time(ts: u64, now: u64) -> String {
    if ts == 0 {
        return "unknown".into();
    }
    if now <= ts {
        return "just now".into();
    }
    let d = now - ts;
    if d < 60 {
        format!("{d}s ago")
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

fn print_log_entry(e: &LogEntry, now: u64) {
    let merge = if e.parents.len() > 1 { " merge" } else { "" };
    let changed = if e.changed.is_empty() {
        "(no content change)".to_string()
    } else if e.changed.len() <= 4 {
        e.changed.join(", ")
    } else {
        format!(
            "{}, +{} more",
            e.changed[..3].join(", "),
            e.changed.len() - 3
        )
    };
    println!(
        "{}  {:<9}  dev {}{merge}  {changed}",
        &hex(&e.commit_id)[..12],
        rel_time(e.ts, now),
        &hex(&e.device_id)[..8]
    );
}

fn print_path_version(v: &PathVersion, now: u64) {
    let what = if !v.present {
        "deleted"
    } else if v.is_dir {
        "changed (dir)"
    } else {
        "modified"
    };
    println!(
        "{}  {:<9}  dev {}  {what}",
        &hex(&v.commit_id)[..12],
        rel_time(v.ts, now),
        &hex(&v.device_id)[..8]
    );
}

/// Open a linked folder's repository for reading history into a throwaway store; returns what history commands need.
async fn open_history(
    rem: &QuicRemote<'_>,
    device: &DeviceKey,
    sdir: &Path,
    link: &Link,
    store: &Store,
) -> CliResult<Option<(Keyring, [u8; 32])>> {
    let (mk, st, anchor) = open_repo_remote(rem, device, &link.rfp, link.anchor).await?;
    persist_anchor(sdir, &link.rfp, anchor)?;
    let keyring = data_keyring_remote(rem, &mk, &st).await?;
    let Some(rh) = fetch_verified_head(rem, &keyring, &st.members, REF).await? else {
        return Ok(None);
    };
    secsec_client::history::fetch_history(
        rem,
        store,
        &keyring,
        &st.ever_members,
        &rh.head.commit_id,
    )
    .await?;
    Ok(Some((keyring, rh.head.commit_id)))
}

async fn run_log(path: Option<String>, key: KeyArgs) -> CliResult<()> {
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let (root, sdir, link) = find_linked(&cwd)?;
    // The synced root itself means the whole repository.
    let path = path
        .map(|p| repo_path(&root, &cwd, &p))
        .transpose()?
        .filter(|p| !p.is_empty());
    let device = load_device(&key)?;
    let cfg = Config::load()?;
    let (endpoint, conn, t) = connect_linked(&link, &device, cfg.tuning()).await?;
    let rem = QuicRemote::new(&conn, t, &device);
    // A throwaway store: the folder's cache belongs to its running sync.
    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let now = unix_secs();
    match open_history(&rem, &device, &sdir, &link, &store).await? {
        None => println!("no history yet: nothing has been synced."),
        Some((keyring, head)) => match &path {
            None => {
                let log = secsec_client::history::repo_log(&keyring, &store, &head)?;
                for e in &log {
                    print_log_entry(e, now);
                }
                println!("{} commit(s).", log.len());
            }
            Some(p) => {
                let hist = secsec_client::history::path_history(&keyring, &store, &head, p)?;
                if hist.is_empty() {
                    println!("no history for '{p}' (it may never have been synced).");
                } else {
                    for v in &hist {
                        print_path_version(v, now);
                    }
                    println!("{} version(s) of '{p}'.", hist.len());
                }
            }
        },
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

async fn run_restore(path: String, version: Option<String>, key: KeyArgs) -> CliResult<()> {
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let (root, sdir, link) = find_linked(&cwd)?;
    let path = repo_path(&root, &cwd, &path)?;
    if path.is_empty() {
        return Err("name a file or folder inside the synced folder to restore".into());
    }
    let device = load_device(&key)?;
    let cfg = Config::load()?;
    let (endpoint, conn, t) = connect_linked(&link, &device, cfg.tuning()).await?;
    let rem = QuicRemote::new(&conn, t, &device);
    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let (keyring, head) = open_history(&rem, &device, &sdir, &link, &store)
        .await?
        .ok_or("no history yet: nothing to restore")?;

    let target = match version {
        Some(prefix) => {
            let prefix = prefix.to_lowercase();
            let ids = secsec_client::history::commit_ids(&keyring, &store, &head)?;
            let matches: Vec<[u8; 32]> = ids
                .into_iter()
                .filter(|c| hex(c).starts_with(&prefix))
                .collect();
            match matches.as_slice() {
                [c] => *c,
                [] => return Err(format!("no commit matches '{prefix}' (see `secsec log`)").into()),
                _ => {
                    return Err(format!(
                        "'{prefix}' matches more than one commit; use a longer prefix"
                    )
                    .into())
                }
            }
        }
        None => {
            // Present on disk: the version before the current one; gone: the latest that existed. Deletions never count.
            let hist = secsec_client::history::path_history(&keyring, &store, &head, &path)?;
            let on_disk = std::fs::symlink_metadata(root.join(&path)).is_ok();
            hist.iter()
                .skip(usize::from(on_disk))
                .find(|v| v.present)
                .map(|v| v.commit_id)
                .ok_or_else(|| format!("'{path}' has no earlier version to restore"))?
        }
    };

    secsec_client::history::restore(&rem, &store, &keyring, &target, &path, &root).await?;
    println!(
        "restored '{path}' from commit {}; the running sync propagates it (or run `secsec sync`).",
        &hex(&target)[..12]
    );
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

// ---- revoke ----

async fn run_revoke(prefix: String, start: PathBuf, yes: bool, key: KeyArgs) -> CliResult<()> {
    let (_root, sdir, link) = find_linked(&start)?;
    let device = load_device(&key)?;
    let me = device.device_id()?;
    let cfg = Config::load()?;
    let (endpoint, conn, t) = connect_linked(&link, &device, cfg.tuning()).await?;
    let rem = QuicRemote::new(&conn, t, &device);
    let (_mk, st, anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;

    let wanted = prefix.to_lowercase();
    let matches: Vec<[u8; 32]> = st
        .members
        .keys()
        .filter(|id| hex(&id[..]).starts_with(&wanted))
        .copied()
        .collect();
    let target = match matches.as_slice() {
        [id] => *id,
        [] => return Err(format!("no enrolled device matches '{prefix}'").into()),
        _ => {
            return Err(
                format!("'{prefix}' matches more than one device; use a longer prefix").into(),
            )
        }
    };
    if target == me {
        return Err("refusing to revoke the device you are running this from".into());
    }
    // Grants this device has not yet verified are suspect: they go with the target (§8.1).
    let revoke = Revoke {
        device: target,
        after_seq: link.anchor.map_or(0, |a| a.max_seq.saturating_add(1)),
    };
    let doomed = revoke_preview(&st, &revoke, &me);
    println!("this revokes {} device(s):", doomed.len());
    for id in &doomed {
        let fp = st
            .members
            .get(id)
            .and_then(|p| p.ssh_fingerprint().ok())
            .unwrap_or_else(|| "<unknown>".to_string());
        println!("  {}  {fp}", &hex(id)[..12]);
    }
    if !yes && !confirm("revoke them and rotate the repository key?")? {
        println!("aborted: nothing changed.");
        return Ok(());
    }
    let rot = rotate_repo_remote(
        &rem,
        &device,
        &link.rfp,
        Some(anchor),
        Some(revoke),
        REF,
        unix_secs(),
    )
    .await?;
    persist_anchor(&sdir, &link.rfp, rot.anchor)?;
    println!(
        "revoked {} device(s); the repository key rotated to generation {}",
        rot.revoked.len(),
        rot.mk.generation()
    );
    println!("now remove their public keys from the server's ~/.ssh/authorized_keys so they cannot reconnect.");
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

// ---- reset ----

fn run_reset(dir: PathBuf, yes: bool) -> CliResult<()> {
    let mut targets: Vec<(PathBuf, &str)> = Vec::new();
    if let Ok(abs) = std::fs::canonicalize(&dir) {
        let sdir = state_path(&abs)?;
        if sdir.exists() {
            if let Some(pid) = lock_holder(&sdir)? {
                let who = pid.map_or_else(String::new, |p| format!(" (pid {p})"));
                return Err(format!(
                    "{} is being synced{who}; stop it first with `secsec stop {}`",
                    abs.display(),
                    abs.display()
                )
                .into());
            }
            targets.push((
                sdir,
                "client sync state: link, object cache, rollback anchor, frontier",
            ));
        }
    }
    let repo = dir.join("repo.secsec");
    if repo.is_file() {
        drop(Store::open(&repo).map_err(|e| {
            format!(
                "{} is in use ({e}); stop `secsec serve` first",
                repo.display()
            )
        })?);
        targets.push((repo, "server repository: every device's encrypted data"));
    }
    let hostkey = dir.join("hostkey");
    for name in ["hostkey.crt", "hostkey.key"] {
        let p = hostkey.join(name);
        if p.is_file() {
            targets.push((p, "server host key: clients must verify a new pin"));
        }
    }
    if targets.is_empty() {
        println!("nothing to reset: no secsec state at {}", dir.display());
        return Ok(());
    }
    println!("this permanently removes:");
    for (path, what) in &targets {
        println!("  {}\n      {what}", path.display());
    }
    println!("your files and your ~/.ssh keys stay.");
    if !yes && !confirm("proceed?")? {
        println!("aborted: nothing removed.");
        return Ok(());
    }
    for (path, _) in &targets {
        if path.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        println!("removed {}", path.display());
    }
    // The host-key directory goes only once nothing else is left in it.
    let _ = std::fs::remove_dir(&hostkey);
    println!("reset complete.");
    Ok(())
}

// ---- main ----

fn run(cli: Cli) -> CliResult<()> {
    let rt = || tokio::runtime::Runtime::new();
    let here = || PathBuf::from(".");
    match cli.cmd {
        Cmd::Serve { dir, port } => rt()?.block_on(run_serve(dir.unwrap_or_else(here), port)),
        Cmd::Sync {
            dir,
            server,
            pin,
            invite,
            once,
            key,
        } => rt()?.block_on(run_sync(
            dir.unwrap_or_else(here),
            SyncArgs {
                server,
                pin,
                invite,
                once,
                key,
            },
        )),
        Cmd::Stop { dir } => run_stop(dir.unwrap_or_else(here)),
        Cmd::Status { dir } => run_status(dir.unwrap_or_else(here)),
        Cmd::Invite { dir, key } => rt()?.block_on(run_invite(dir.unwrap_or_else(here), key)),
        Cmd::Devices { dir, key } => rt()?.block_on(run_devices(dir.unwrap_or_else(here), key)),
        Cmd::Hostpin { dir, serve } => run_hostpin(dir.unwrap_or_else(here), serve),
        Cmd::Log { path, key } => rt()?.block_on(run_log(path, key)),
        Cmd::Restore { path, version, key } => rt()?.block_on(run_restore(path, version, key)),
        Cmd::Revoke {
            device,
            dir,
            yes,
            key,
        } => rt()?.block_on(run_revoke(device, dir.unwrap_or_else(here), yes, key)),
        Cmd::Reset { dir, yes } => run_reset(dir.unwrap_or_else(here), yes),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_parse_every_form() {
        let v4: SocketAddr = "192.0.2.7:9000".parse().unwrap();
        assert_eq!(resolve_server("192.0.2.7:9000").unwrap(), v4);
        assert_eq!(resolve_server("192.0.2.7").unwrap().port(), DEFAULT_PORT);
        assert_eq!(
            resolve_server("[::1]:9000").unwrap(),
            "[::1]:9000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(resolve_server("::1").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve_server("[::1]").unwrap().port(), DEFAULT_PORT);
        assert_eq!(resolve_server("localhost:9001").unwrap().port(), 9001);
        assert!(resolve_server("localhost:notaport").is_err());
    }

    #[test]
    fn repository_paths_are_relative_to_the_working_directory() {
        let root = Path::new("/r");
        assert_eq!(repo_path(root, Path::new("/r"), "a/b").unwrap(), "a/b");
        assert_eq!(
            repo_path(root, Path::new("/r/docs"), "x.md").unwrap(),
            "docs/x.md"
        );
        assert_eq!(repo_path(root, Path::new("/r/docs"), "../y").unwrap(), "y");
        assert_eq!(repo_path(root, Path::new("/r/docs"), "/r/z").unwrap(), "z");
        assert!(repo_path(root, Path::new("/r"), "../escape").is_err());
        assert!(repo_path(root, Path::new("/r"), "/elsewhere").is_err());
        assert_eq!(repo_path(root, Path::new("/r/docs"), ".").unwrap(), "docs");
    }

    #[test]
    fn config_clamps_to_its_documented_range() {
        let mut c = Config::default();
        c.apply("quic_idle_secs", "18446744073709551615");
        c.apply("quic_keepalive_secs", "0");
        c.apply("poll_interval_secs", "1");
        c.apply("listen_port", "0");
        c.apply("max_connections", "0");
        c.clamp();
        assert_eq!(c.quic_idle_secs, Tuning::MAX_IDLE_SECS);
        assert_eq!(c.quic_keepalive_secs, 1);
        assert_eq!(c.poll_interval_secs, 5);
        assert_eq!(c.listen_port, DEFAULT_PORT);
        assert_eq!(c.max_connections, 1);
    }

    #[test]
    fn a_link_round_trips_and_its_anchor_only_advances() {
        let dir = tempfile::tempdir().unwrap();
        let rfp = [7; 32];
        let link = Link {
            server: "host:1".into(),
            host_id: [1; 32],
            rfp,
            anchor: Some(RosterAnchor {
                max_seq: 3,
                tip_hash: [2; 32],
            }),
        };
        write_link(dir.path(), &link).unwrap();
        let older = RosterAnchor {
            max_seq: 2,
            tip_hash: [9; 32],
        };
        persist_anchor(dir.path(), &rfp, older).unwrap();
        assert_eq!(
            read_link(dir.path())
                .unwrap()
                .unwrap()
                .anchor
                .unwrap()
                .max_seq,
            3
        );
        let newer = RosterAnchor {
            max_seq: 5,
            tip_hash: [5; 32],
        };
        persist_anchor(dir.path(), &[8; 32], newer).unwrap();
        assert_eq!(
            read_link(dir.path())
                .unwrap()
                .unwrap()
                .anchor
                .unwrap()
                .max_seq,
            3
        );
        persist_anchor(dir.path(), &rfp, newer).unwrap();
        let got = read_link(dir.path()).unwrap().unwrap();
        assert_eq!(got.anchor, Some(newer));
        assert_eq!(got.server, "host:1");
    }

    #[test]
    fn the_folder_lock_is_exclusive_and_names_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        assert!(lock_holder(dir.path()).unwrap().is_none());
        let held = FolderLock::acquire(dir.path(), dir.path()).unwrap();
        #[cfg(unix)]
        assert_eq!(
            lock_holder(dir.path()).unwrap(),
            Some(Some(std::process::id()))
        );
        // Windows locks the whole file against every other handle, so the holder's pid is unreadable there.
        #[cfg(not(unix))]
        assert!(lock_holder(dir.path()).unwrap().is_some());
        assert!(FolderLock::acquire(dir.path(), dir.path()).is_err());
        drop(held);
        assert!(lock_holder(dir.path()).unwrap().is_none());
        assert!(wait_unlocked(dir.path(), Some(Duration::from_secs(5))).unwrap());
    }
}
