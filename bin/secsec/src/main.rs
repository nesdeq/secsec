//! `secsec` — the CLI binary (`secsec-Design.md` §11, §12): `serve` (the blind server, gated on the
//! operator's `authorized_keys`), `sync` (link a folder and keep it in continuous two-way sync; one
//! repo = one tree under the ref `main`), `invite` / `devices` / `revoke` (enrollment lifecycle,
//! §7/§8.4), `hostpin` (§11 TOFU verification), `log` / `restore` (history), and `reset` (wipe local
//! secsec state). Usage: README.md.

#![allow(missing_docs)] // a binary crate exports no public API

use clap::{Parser, Subcommand};
use secsec_client::pair;
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{
    data_keyring_remote, init_repo_remote, open_repo_remote, RepoError, RosterAnchor,
};
use secsec_client::sync::sync_once;
use secsec_client::{load_frontier, save_frontier, FrontierLoad};
use secsec_proto::server::{Limits, WindowCounter};
use secsec_server::{serve::serve_connection, Server};
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_sync::rollback::SyncFrontier;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{client_config_tofu, client_config_tuned, server_config_tuned, Tuning};
use secsec_transport::HostPin;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Default listen port a client assumes for a bare `host` (§19: udp/8899). The server's actual listen
/// port, the staging TTL, the reclaim cadence, and history retention are set in `secsec.config` (§7).
const DEFAULT_PORT: u16 = 8899;
/// How long `invite` waits for a device to pair, and `sync --invite` waits for the host, in 500 ms
/// pairing-poll rounds (§7): the host waits up to the ~10-minute invite lifetime; the joiner ~2 min.
const PAIR_HOST_ROUNDS: u32 = 1200;
const PAIR_JOIN_ROUNDS: u32 = 240;

#[derive(Parser)]
#[command(
    name = "secsec",
    about = "Zero-knowledge end-to-end-encrypted file sync"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the blind sync server. Reads `~/.ssh/authorized_keys` as a mandatory connection gate.
    Serve {
        /// Directory to store the encrypted repo + host key (default: current directory).
        dir: Option<PathBuf>,
        /// UDP port to listen on (default: 8899).
        port: Option<u16>,
    },
    /// Sync a folder with a repo, continuously. Name the server once; then just `secsec sync <dir>`.
    Sync {
        /// The folder to sync (default: current directory).
        dir: Option<PathBuf>,
        /// Server `host[:port]` — required the first time a folder is linked.
        #[arg(long)]
        server: Option<String>,
        /// A one-time invite code from an enrolled device (to join an existing repo).
        #[arg(long)]
        invite: Option<String>,
        /// Sync once and exit (default is to keep running and watch for changes).
        #[arg(long)]
        once: bool,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// On an enrolled device, print a one-time invite code and pair a new device over the wire.
    Invite {
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// List the devices enrolled in a linked folder's repo (with their SSH key fingerprints).
    Devices {
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Show the pinned server host fingerprint for a folder, to compare out-of-band against the
    /// `host pin` the server prints on startup (TOFU first-contact verification).
    Hostpin {
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
    },
    /// Show the change log of the synced folder you're in; with a path, that file/folder's history.
    Log {
        /// A file or folder within the repo (relative to the synced folder root). Omit for the whole repo.
        path: Option<String>,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Restore a historic version of a file/folder into the working folder; the next sync propagates it
    /// to other devices (like copying the old file over the current one). Run inside the synced folder.
    Restore {
        /// The file or folder within the repo to restore (relative to the synced folder root).
        path: String,
        /// The version: a commit-id prefix from `secsec log <path>`. Omit for the previous version.
        version: Option<String>,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Revoke a device (e.g. a stolen one): rotate the key away from it so it can't read new data.
    Revoke {
        /// The device id (a unique prefix is enough) — from `secsec devices`.
        device: String,
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
        /// SSH private key to use as this device's identity (default: ~/.ssh/id_ed25519).
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Read the key passphrase from stdin instead of prompting — for headless/GUI launchers.
        /// The passphrase travels over a pipe, never argv, so it is not visible to `ps`/`top`.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Wipe secsec's local state at a location (client link/cache and/or server repo + host key) and
    /// start over — your files and your `~/.ssh` key are left untouched. Stop a running sync/serve first.
    Reset {
        /// The synced folder and/or serve dir to reset (default: current directory).
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

fn parse_hex(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if s.len() % 2 != 0 {
        return Err("invalid hex (odd length)".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid hex".into())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    parse_hex(s.trim())?
        .try_into()
        .map_err(|_| "expected 32 bytes (64 hex chars)".into())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rand32() -> Result<[u8; 32], Box<dyn Error>> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n)?;
    Ok(n)
}

/// A fresh 16-byte per-attempt push id (§3).
fn rand16() -> Result<[u8; 16], Box<dyn Error>> {
    let mut n = [0u8; 16];
    getrandom::fill(&mut n)?;
    Ok(n)
}

fn home() -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

/// Load this device's SSH key — the `--key <file>` override if given, else the default
/// `~/.ssh/id_ed25519` (current behaviour when the flag is absent) — decrypting a
/// passphrase-protected key in memory; the on-disk key stays encrypted. When `passphrase_stdin` is
/// set the passphrase is read from stdin (for headless/GUI launchers); otherwise we prompt
/// interactively with no echo.
fn load_device(
    key_path: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<DeviceKey, Box<dyn Error>> {
    let path = match key_path {
        Some(p) => p,
        None => home()?.join(".ssh/id_ed25519"),
    };
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read device key {}: {e}", path.display()))?;
    match DeviceKey::from_openssh(&pem) {
        Ok(device) => Ok(device),
        Err(secsec_sig::SigError::Encrypted) if passphrase_stdin => decrypt_device_stdin(&pem),
        Err(secsec_sig::SigError::Encrypted) => decrypt_device(&pem, &path),
        Err(e) => Err(e.into()),
    }
}

/// Prompt for the passphrase (up to 3 attempts, no echo) and decrypt the key in RAM; the typed
/// passphrase is zeroized after each try and the on-disk key is never modified.
fn decrypt_device(pem: &str, path: &Path) -> Result<DeviceKey, Box<dyn Error>> {
    const MAX_TRIES: usize = 3;
    for attempt in 1..=MAX_TRIES {
        let passphrase = Zeroizing::new(rpassword::prompt_password(format!(
            "passphrase for {}: ",
            path.display()
        ))?);
        match DeviceKey::from_openssh_passphrase(pem, &passphrase) {
            Ok(device) => return Ok(device),
            // Wrong passphrase: re-prompt unless that was the last allowed attempt.
            Err(secsec_sig::SigError::BadPassphrase) => {
                if attempt < MAX_TRIES {
                    eprintln!("wrong passphrase — try again");
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err("could not decrypt the device key: wrong passphrase".into())
}

/// Decrypt a passphrase-protected key using a passphrase read from **stdin** (the headless / GUI
/// path). A parent process writes the passphrase to this child's stdin and closes it — so the secret
/// travels over a pipe and never appears in argv (invisible to `ps`/`top`/`/proc/<pid>/cmdline`),
/// unlike a `--passphrase <value>` flag would. One attempt only: stdin carries a single passphrase.
fn decrypt_device_stdin(pem: &str) -> Result<DeviceKey, Box<dyn Error>> {
    let passphrase = read_passphrase_stdin()?;
    match DeviceKey::from_openssh_passphrase(pem, &passphrase) {
        Ok(device) => Ok(device),
        Err(secsec_sig::SigError::BadPassphrase) => {
            Err("wrong passphrase (read from stdin)".into())
        }
        Err(e) => Err(e.into()),
    }
}

/// Read a passphrase from stdin: take the first line, strip its trailing newline (CRLF tolerated),
/// and keep it [`Zeroizing`]. Other whitespace is preserved (it may be part of the passphrase); EOF
/// with no trailing newline is fine — the parent may close the pipe without one.
fn read_passphrase_stdin() -> Result<Zeroizing<String>, Box<dyn Error>> {
    use std::io::BufRead;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(Zeroizing::new(
        line.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

/// The secsec client root: `$XDG_CONFIG_HOME/secsec` if that var is an absolute path, else
/// `~/.config/secsec`. Everything client-side (per-folder state, the UI's `ui.conf`/log, the systemd
/// env files) lives under this one root — no scatter across the home dir (§13). Resolves to the same
/// dir the GNOME/macOS UIs use via the XDG config dir.
fn config_root() -> Result<PathBuf, Box<dyn Error>> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => home()?.join(".config"),
    };
    Ok(base.join("secsec"))
}

// ---- secsec.config (§7) ----

/// Operator-tunable settings, loaded from `<config_root>/secsec.config` (written with defaults on
/// first use). Only settings that are safe to change live here; content-addressing, the wire format,
/// and cryptographic parameters are compiled in. Out-of-range values are clamped on load.
struct Config {
    // [client]
    retention_keep_versions: usize,
    watch_debounce_ms: u64,
    poll_interval_secs: u64,
    quic_idle_secs: u64,
    quic_keepalive_secs: u64,
    // [server]
    listen_port: u16,
    storage_cap_gib: u64,
    write_rate_mb_s: u64,
    read_rate_mb_s: u64,
    conn_rate_per_ip: u64,
    max_conns_per_key: u64,
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
            staging_ttl_hours: 24,
            reclaim_tick_minutes: 60,
        }
    }
}

/// The default `secsec.config`, written verbatim on first use. Comments document each setting's range.
const CONFIG_TEMPLATE: &str = "\
# secsec.config — operator-tunable settings. Out-of-range values are clamped on load.
# Only settings that are safe to change are here; content-addressing, the wire format, and
# cryptographic parameters are compiled in and cannot be set from this file.

[client]
retention_keep_versions = 8     # versions kept per file (0 = keep every version forever)
watch_debounce_ms       = 1000  # coalesce a burst of edits into one sync (min 100)
poll_interval_secs      = 15    # periodic re-sync to pick up newly-enrolled devices (min 5)
quic_idle_secs          = 30    # connection idle timeout (min 5)
quic_keepalive_secs     = 10    # keepalive interval (min 1, forced below quic_idle_secs)

[server]
listen_port          = 8899  # UDP port to listen on (1-65535)
storage_cap_gib      = 0     # per-key cumulative new-write cap, GiB (0 = unlimited)
write_rate_mb_s      = 100   # per-key sustained write rate, MB/s (min 1)
read_rate_mb_s       = 200   # per-key sustained read rate, MB/s (min 1)
conn_rate_per_ip     = 10    # new connections per second per source IP (min 1)
max_conns_per_key    = 3     # concurrent connections per device key (min 1)
staging_ttl_hours    = 24    # idle hours before an abandoned upload's staging is reclaimed (min 1)
reclaim_tick_minutes = 60    # how often the server sweeps idle staging (min 1)
";

impl Config {
    /// Load the config, writing the default template on first use; values are range-clamped (§7).
    fn load() -> Result<Config, Box<dyn Error>> {
        let path = config_root()?.join("secsec.config");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, CONFIG_TEMPLATE)?;
                CONFIG_TEMPLATE.to_string()
            }
        };
        let mut cfg = Config::default();
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('[') {
                continue; // blank, comment, or section header
            }
            if let Some((k, v)) = line.split_once('=') {
                cfg.apply(k.trim(), v.trim());
            }
        }
        cfg.clamp();
        Ok(cfg)
    }

    /// Set one field from a `key = value` line; an unknown key or an unparseable value is ignored so
    /// the compiled-in default stands.
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
            "staging_ttl_hours" => set(&mut self.staging_ttl_hours, val),
            "reclaim_tick_minutes" => set(&mut self.reclaim_tick_minutes, val),
            _ => {}
        }
    }

    /// Clamp every field to its safe range (§7). `retention_keep_versions == 0` (keep everything) and
    /// `storage_cap_gib == 0` (unlimited) are valid and left as-is.
    fn clamp(&mut self) {
        self.watch_debounce_ms = self.watch_debounce_ms.max(100);
        self.poll_interval_secs = self.poll_interval_secs.max(5);
        self.quic_idle_secs = self.quic_idle_secs.max(5);
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
        self.staging_ttl_hours = self.staging_ttl_hours.max(1);
        self.reclaim_tick_minutes = self.reclaim_tick_minutes.max(1);
    }

    /// The transport idle/keepalive tuning derived from this config.
    fn tuning(&self) -> Tuning {
        Tuning {
            idle_secs: self.quic_idle_secs,
            keepalive_secs: self.quic_keepalive_secs,
        }
    }

    /// The server runtime limits derived from this config: rates decimal-MB/s → bytes/s, cap GiB →
    /// bytes (0 = unlimited). Saturating so a huge value cannot overflow.
    fn limits(&self) -> Limits {
        Limits {
            write_rate: self.write_rate_mb_s.saturating_mul(1_000_000),
            read_rate: self.read_rate_mb_s.saturating_mul(1_000_000),
            conn_rate_per_sec: self.conn_rate_per_ip,
            max_conns_per_key: self.max_conns_per_key,
            storage_cap: self.storage_cap_gib.saturating_mul(1024 * 1024 * 1024),
        }
    }
}

/// Parse `val` into `field` via `FromStr`, leaving the existing value on a parse error.
fn set<T: std::str::FromStr>(field: &mut T, val: &str) {
    if let Ok(v) = val.parse() {
        *field = v;
    }
}

/// The out-of-tree state directory for a synced folder: `<config_root>/folders/<hash(abspath)>/`
/// (created if absent). Holds the per-folder link, the sealed cursor, the receipt log, and the object
/// cache — so the synced folder itself stays nothing but the user's files. A pre-consolidation dir
/// (`~/.local/state/secsec/<hash>`) is migrated on first use, so an existing link keeps its frontier.
fn state_dir_for(dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let abs = std::fs::canonicalize(dir)?;
    let name = hex(blake3::hash(abs.to_string_lossy().as_bytes()).as_bytes());
    let sdir = config_root()?.join("folders").join(&name);
    // Migrate the legacy ~/.local/state location (best-effort; same filesystem in practice) so an
    // upgrader doesn't lose its anti-rollback frontier and re-clone.
    if !sdir.exists() {
        if let Ok(home) = home() {
            let legacy = home.join(".local/state/secsec").join(&name);
            if legacy.is_dir() {
                if let Some(parent) = sdir.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let _ = std::fs::rename(&legacy, &sdir);
            }
        }
    }
    std::fs::create_dir_all(&sdir)?;
    Ok(sdir)
}

/// Resolve `host[:port]` (default port 8899) to a socket address.
fn resolve_server(s: &str) -> Result<SocketAddr, Box<dyn Error>> {
    let with_port = if s
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .is_some()
        && s.contains(':')
    {
        s.to_string()
    } else {
        format!("{s}:{DEFAULT_PORT}")
    };
    with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("cannot resolve server address '{s}'").into())
}

/// A folder's link to its repo (the git-remote analogue): server address, pinned host id, RFP, ref
/// name, and the §8.1 anti-rollback anchor (P7). Stored at `<state>/link` — client-side, so a
/// malicious **server** cannot roll the roster back.
struct Link {
    server: String,
    host_id: [u8; 32],
    rfp: [u8; 32],
    ref_name: String,
    anchor: Option<RosterAnchor>,
}

fn read_link(sdir: &Path) -> Option<Link> {
    let s = std::fs::read_to_string(sdir.join("link")).ok()?;
    let (mut server, mut host_id, mut rfp, mut ref_name) = (None, None, None, None);
    let (mut rseq, mut rtip) = (None, None);
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("server=") {
            server = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("host_id=") {
            host_id = parse_hex32(v).ok();
        } else if let Some(v) = line.strip_prefix("rfp=") {
            rfp = parse_hex32(v).ok();
        } else if let Some(v) = line.strip_prefix("ref=") {
            ref_name = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("roster_seq=") {
            rseq = v.parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("roster_tip=") {
            rtip = parse_hex32(v).ok();
        }
    }
    // None until the first successful cold-start records one — the create/join establishes it.
    let anchor = match (rseq, rtip) {
        (Some(max_seq), Some(tip_hash)) => Some(RosterAnchor { max_seq, tip_hash }),
        _ => None,
    };
    Some(Link {
        server: server?,
        host_id: host_id?,
        rfp: rfp?,
        ref_name: ref_name?,
        anchor,
    })
}

fn write_link(sdir: &Path, l: &Link) -> Result<(), Box<dyn Error>> {
    let mut body = format!(
        "server={}\nhost_id={}\nrfp={}\nref={}\n",
        l.server,
        hex(&l.host_id),
        hex(&l.rfp),
        l.ref_name
    );
    if let Some(a) = &l.anchor {
        body.push_str(&format!(
            "roster_seq={}\nroster_tip={}\n",
            a.max_seq,
            hex(&a.tip_hash)
        ));
    }
    std::fs::write(sdir.join("link"), body)?;
    Ok(())
}

/// Connect to `addr`, pinning a known `host_id` or capturing it on first use (TOFU). Returns the
/// endpoint, connection, and the pinned/captured `host_id`.
async fn connect(
    addr: SocketAddr,
    pinned: Option<[u8; 32]>,
    tuning: Tuning,
) -> Result<(quinn::Endpoint, quinn::Connection, [u8; 32]), Box<dyn Error>> {
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    let captured = match pinned {
        Some(h) => {
            ep.set_default_client_config(client_config_tuned(HostPin::from_host_id(h), tuning)?);
            None
        }
        None => {
            let (cfg, cap) = client_config_tofu()?;
            ep.set_default_client_config(cfg);
            Some(cap)
        }
    };
    let conn = ep.connect(addr, "secsec.invalid")?.await?;
    let host_id = match (pinned, captured) {
        (Some(h), _) => h,
        (None, Some(cap)) => {
            (*cap.lock().expect("tofu cell")).ok_or("server presented no host key during TOFU")?
        }
        _ => unreachable!(),
    };
    Ok((ep, conn, host_id))
}

// ---- host key (server) ----

fn load_or_generate_hostkey(dir: &Path) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let cert_path = dir.join("hostkey.crt");
    let key_path = dir.join("hostkey.key");
    if cert_path.exists() && key_path.exists() {
        return Ok((std::fs::read(cert_path)?, std::fs::read(key_path)?));
    }
    let ck = rcgen::generate_simple_self_signed(vec!["secsec.invalid".to_string()])?;
    let (cert, key) = (ck.cert.der().to_vec(), ck.key_pair.serialize_der());
    std::fs::create_dir_all(dir)?;
    std::fs::write(&cert_path, &cert)?;
    std::fs::write(&key_path, &key)?;
    Ok((cert, key))
}

// ---- serve ----

async fn run_serve(dir: PathBuf, port: Option<u16>) -> Result<(), Box<dyn Error>> {
    let cfg = Config::load()?;
    let port = port.unwrap_or(cfg.listen_port);
    std::fs::create_dir_all(&dir)?;
    let store_path = dir.join("repo.secsec");
    let hostkey_dir = dir.join("hostkey");
    let auth_path = home()?.join(".ssh/authorized_keys");

    // authorized_keys is MANDATORY (the connection gate for all comms). Refuse to start without it.
    let body = std::fs::read_to_string(&auth_path).map_err(|e| {
        format!("authorized_keys is required: cannot read {} ({e}). secsec serve gates every connection on it.", auth_path.display())
    })?;
    let authorized = secsec_server::parse_authorized_keys(&body);
    if authorized.is_empty() {
        return Err(format!(
            "{} has no usable Ed25519 keys — add at least your own device's public key",
            auth_path.display()
        )
        .into());
    }

    let (cert, key) = load_or_generate_hostkey(&hostkey_dir)?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    let store = Store::open(&store_path)?;
    let server = std::sync::Arc::new(
        Server::new(store)
            .with_limits(cfg.limits())
            .with_authorized_file(auth_path.clone()), // re-read per connection
    );

    // Background reclaimer: drop in-flight pushes idle past the staging TTL (§3), so abandoned staging
    // cannot accumulate on a server no client is actively pushing to (the accept loop never fires when
    // idle, so the sweep needs its own timer).
    {
        let server = server.clone();
        let staging_ttl_secs = cfg.staging_ttl_hours.saturating_mul(3600);
        let reclaim_tick_secs = cfg.reclaim_tick_minutes.saturating_mul(60);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(reclaim_tick_secs));
            loop {
                tick.tick().await;
                if let Err(e) = server.reclaim_staging(unix_secs(), staging_ttl_secs) {
                    eprintln!("staging reclaim failed: {e}");
                }
            }
        });
    }

    let listen: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    let endpoint = quinn::Endpoint::server(server_config_tuned(&cert, &key, cfg.tuning())?, listen)?;
    println!(
        "secsec serve — store {} · host pin {}",
        store_path.display(),
        hex(&host_id)
    );
    println!(
        "authorized_keys: {} ({} key(s)) · listening on {}",
        auth_path.display(),
        authorized.len(),
        endpoint.local_addr()?
    );
    // Per-source-IP new-connection rate limit (configurable, §7/§19). The accept loop is a single
    // task, so this map needs no lock; it is pruned at most once per window so idle source IPs cannot
    // accumulate.
    let conn_rate = server.conn_rate_per_sec();
    let mut ip_rate: std::collections::HashMap<std::net::IpAddr, WindowCounter> =
        std::collections::HashMap::new();
    let mut last_prune = 0u64;
    while let Some(incoming) = endpoint.accept().await {
        let now = unix_secs();
        // §11 DoS hardening: validate the source address with a stateless QUIC Retry before
        // allocating connection state — anti-amplification, and a spoofed IP cannot exhaust
        // another's per-IP rate budget.
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
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
        let server = server.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = serve_connection(&conn, &server, host_id, unix_secs).await {
                        eprintln!("connection closed: {e}");
                    }
                }
                Err(e) => eprintln!("accept failed: {e}"),
            }
        });
    }
    Ok(())
}

// ---- sync ----

async fn run_sync(
    dir: PathBuf,
    server_opt: Option<String>,
    invite_opt: Option<String>,
    once: bool,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(&dir)?;
    let sdir = state_dir_for(&dir)?;
    let device = load_device(key, passphrase_stdin)?;
    let link = read_link(&sdir);
    let cfg = Config::load()?;

    let server_str = server_opt
        .clone()
        .or_else(|| link.as_ref().map(|l| l.server.clone()))
        .ok_or("no server for this folder — pass --server host[:port] the first time")?;
    let addr = resolve_server(&server_str)?;
    // One repo holds exactly one synced tree under the ref `main`, so devices converge with zero
    // flags regardless of their local folder names. (Independent trees use independent repos.)
    let ref_name = "main".to_string();

    // Connect: pin the saved host key, or TOFU on first contact.
    let pinned = link.as_ref().map(|l| l.host_id);
    let (mut endpoint, mut conn, host_id) = connect(addr, pinned, cfg.tuning()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let mut transcript = sess.transcript;
    let rem = QuicRemote::new(&conn, transcript, &device);

    // Establish the RFP: join via invite, reuse the link, or create the repo (first device).
    let rfp = if let Some(code_str) = invite_opt {
        let code = pair::decode_code(&code_str)?;
        println!("pairing with an enrolled device…");
        pair::run_join(&rem, &device, &code, &host_id, PAIR_JOIN_ROUNDS).await?
    } else if let Some(l) = &link {
        l.rfp
    } else {
        // First device: attempt to create the repo. Genesis is permitted only while the roster is
        // empty, so if the repo already exists this fails and the device must join with an invite.
        // (No pre-probe: reads require enrollment, which we don't have yet.)
        if pinned.is_none() {
            println!(
                "server host fingerprint (verify out-of-band): {}",
                hex(&host_id)
            );
        }
        match init_repo_remote(&rem, &device, unix_secs()).await {
            Ok(rfp) => {
                println!("created new repository");
                rfp
            }
            // This device is already a member of the repo, but this folder isn't linked to it — so
            // don't (and the library won't) re-run genesis over its live keyslot.
            Err(RepoError::AlreadyEnrolled) => {
                return Err(format!(
                    "this device is already enrolled in the repo on {server_str}, but this folder isn't linked to it. \
                     Sync the folder you first linked here, or re-establish this one: run `secsec invite` on an enrolled \
                     device and `secsec sync {} --server {server_str} --invite <code>` here.",
                    dir.display()
                )
                .into());
            }
            Err(e) => {
                return Err(format!(
                    "could not create the repository (it likely already exists) — to join it, get an invite from an enrolled device and pass --invite <code>. ({e})"
                )
                .into());
            }
        }
    };

    // Cold-start over the wire (P7 anti-rollback: the fetched chain must extend the persisted anchor).
    let prev_anchor = link.as_ref().and_then(|l| l.anchor);
    let was_linked = link.is_some();
    let (mk, mut st, mut anchor) = open_repo_remote(&rem, &device, &rfp, prev_anchor).await?;
    // Persist the link with the advanced anti-rollback anchor.
    write_link(
        &sdir,
        &Link {
            server: server_str.clone(),
            host_id,
            rfp,
            ref_name: ref_name.clone(),
            anchor: Some(anchor),
        },
    )?;
    // The roster_seq stamped on commits/heads is the current sigchain tip (drives §10 gate 1).
    let mut roster_seq = anchor.max_seq;

    let mut keyring = data_keyring_remote(&rem, &mk).await?;
    let store = Store::open(sdir.join("objects.secsec"))?;
    let frontier_path = sdir.join("frontier");
    let base_path = sdir.join("base");
    // The per-attempt push id (§3): persisted before each push, removed after; a file left behind by a
    // crash mid-push is reused on the next run so the resumed push re-sends only what is still missing.
    let push_id_path = sdir.join("push_id");
    let mut resume_push_id: Option<[u8; 16]> = std::fs::read(&push_id_path)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b).ok());
    let mut frontier = match load_frontier(&frontier_path, &device)? {
        FrontierLoad::Loaded(f) => f,
        FrontierLoad::Absent => {
            // §8.5 lost-frontier event: a folder already linked to a repo whose sealed frontier is
            // gone (disk loss, deletion) is a reinstall — authenticity still holds (RFP + mk_commit),
            // but freshness/rollback gating does not until a peer reconfirms. Alarm prominently.
            if was_linked {
                eprintln!(
                    "warning: local sync state for this folder is missing — treating as a reinstall.\n\
                     anti-rollback freshness is not guaranteed for this session until it reconverges (§8.5)."
                );
            }
            SyncFrontier::default()
        }
    };
    let mut base = match std::fs::read_to_string(&base_path) {
        Ok(s) => Some(parse_hex32(&s)?),
        Err(_) => None,
    };

    // Startup store hygiene, once per session: drop local objects unreachable from our last-synced
    // head (orphans from cas-conflict retries / aborted pushes). Best-effort, never blocks syncing.
    // (Trims the logical set; redb re-grows its file to working size on the next write.)
    if let Some(b) = base {
        match secsec_client::prune::local_sweep(&keyring, &store, &b) {
            Ok(n) if n > 0 => eprintln!("local sweep: dropped {n} unreachable object(s)"),
            _ => {}
        }
    }

    println!(
        "synced '{}' (generation {}, {} member(s)) ↔ {}",
        ref_name,
        mk.generation(),
        st.members.len(),
        dir.display()
    );

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    if !once {
        let wdir = dir.clone();
        let debounce_ms = cfg.watch_debounce_ms;
        std::thread::spawn(move || {
            let _ = secsec_client::watcher::watch_dir(&wdir, Duration::from_millis(debounce_ms), || {
                tx.send(()).is_ok()
            });
        });
        println!("watching {} — Ctrl-C to stop", dir.display());
    }
    let mut poll = tokio::time::interval(Duration::from_secs(cfg.poll_interval_secs));
    poll.tick().await;

    let mut initial = true;
    let mut retry_now = false;
    let mut want_refold = false;
    loop {
        if !initial && !retry_now {
            tokio::select! {
                ev = rx.recv() => { if ev.is_none() { break; } }
                _ = poll.tick() => { want_refold = true; } // periodic: pick up newly-enrolled devices
            }
        }
        retry_now = false;

        // Self-heal a dropped connection: post-sleep the server has discarded ours, so a reconnect
        // handshake succeeds but the link is stateless-reset on first use — verify it with a real
        // round-trip before trusting it, and retry (paced) until it carries data.
        if let Some(reason) = conn.close_reason() {
            eprintln!("connection lost ({reason}) — reconnecting to {server_str}…");
            match reconnect_session(addr, host_id, &device, cfg.tuning()).await {
                Ok((ep, c, t)) => {
                    // Probe with one round-trip; a reset path fails here despite a "good" handshake.
                    let probe = QuicRemote::new(&c, t, &device);
                    if let Err(e) = secsec_client::fetch_head(&probe, &keyring, &ref_name).await {
                        eprintln!("reconnected but the link is still dead ({e}); retrying in 2s…");
                        initial = false;
                        retry_now = true;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    endpoint = ep;
                    conn = c;
                    transcript = t;
                    want_refold = true;
                }
                Err(err) => {
                    eprintln!("reconnect failed: {err}; retrying in 2s…");
                    initial = false;
                    retry_now = true;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }
        }

        let rem = QuicRemote::new(&conn, transcript, &device);

        // Re-fold the roster so a device that enrolled AFTER this loop started is recognized (else its
        // head reads as "signed by a non-member"), and keep `roster_seq` current. Done on the periodic
        // tick and after a reconnect — not on every file-change event, to keep saves snappy.
        let refolded = want_refold;
        if want_refold {
            want_refold = false;
            match open_repo_remote(&rem, &device, &rfp, Some(anchor)).await {
                Ok((m, s, a)) => {
                    // Re-peel the data keyring FIRST so the roster update is all-or-nothing: never
                    // advance the generation without its matching keyring (the head/objects would be
                    // unreadable until the next tick). On a peel failure keep the last-known roster
                    // and retry next cycle.
                    match data_keyring_remote(&rem, &m).await {
                        Ok(k) => {
                            if a.max_seq != anchor.max_seq {
                                let _ = write_link(
                                    &sdir,
                                    &Link {
                                        server: server_str.clone(),
                                        host_id,
                                        rfp,
                                        ref_name: ref_name.clone(),
                                        anchor: Some(a),
                                    },
                                );
                            }
                            st = s;
                            anchor = a;
                            roster_seq = a.max_seq;
                            keyring = k;
                        }
                        Err(e) => {
                            if conn.close_reason().is_none() {
                                eprintln!("roster refresh failed (using last known roster): {e}");
                            }
                        }
                    }
                }
                // A genuine server rollback/reset (P7): only this is fatal; other fold errors are
                // transient below — a glitchy fetch must not permanently stop syncing.
                Err(RepoError::Rollback) => {
                    eprintln!(
                        "ALARM: the repo on {server_str} no longer extends this folder's anti-rollback \
                         anchor (P7) — the server may have been reset or rolled back. Refusing to sync; \
                         re-link with `--invite` if this is intended."
                    );
                    break;
                }
                Err(e) => {
                    if conn.close_reason().is_none() {
                        eprintln!("roster refresh failed (using last known roster): {e}");
                    }
                }
            }
        }

        // §8.5: seal the advanced frontier to disk BEFORE any ref-advancing head push — a crash
        // post-push must not leave a published head uncovered by the persisted frontier.
        // Mint (or resume) the per-attempt push id and persist it before the push (temp+rename), so a
        // crash mid-push can resume it next run; it is removed once the attempt returns.
        let push_id = match resume_push_id.take() {
            Some(p) => p,
            None => rand16()?,
        };
        {
            let tmp = push_id_path.with_extension("tmp");
            std::fs::write(&tmp, push_id)?;
            std::fs::rename(&tmp, &push_id_path)?;
        }
        let seal = |fr: &SyncFrontier| save_frontier(&frontier_path, fr, &device);
        let outcome = sync_once(
            &rem,
            &store,
            &dir,
            &keyring,
            &device,
            &st.members,
            &frontier,
            &ref_name,
            roster_seq,
            base,
            unix_secs(),
            &push_id,
            &seal,
        )
        .await;
        let _ = std::fs::remove_file(&push_id_path);
        match outcome {
            Ok(outcome) => {
                // Persist the final frontier too — it additionally carries our own commit's high-water,
                // which the pre-push seal (observations only) need not have included.
                save_frontier(&frontier_path, &outcome.frontier, &device)?;
                if let Some(b) = outcome.base {
                    std::fs::write(&base_path, hex(&b))?;
                }
                if initial || !matches!(outcome.kind, secsec_client::sync::SyncKind::UpToDate) {
                    println!("sync: {:?}", outcome.kind);
                }
                // Surface keep-both merge conflicts (§10): the conflicting versions are preserved on
                // disk as `name.conflict-<device>-<id>.ext` (no data lost), but the user must be told.
                if !outcome.conflicts.is_empty() {
                    eprintln!(
                        "merge: {} file(s) conflicted and were kept on both sides — review:",
                        outcome.conflicts.len()
                    );
                    for p in &outcome.conflicts {
                        eprintln!("  {p}  →  see the name.conflict-* copy alongside it");
                    }
                }
                frontier = outcome.frontier;
                base = outcome.base;

                // Bound history once per session (best-effort, §5): keep the last N versions per file,
                // deleting superseded content under the head-binding CAS. Never blocks syncing.
                if initial {
                    if let Err(e) = secsec_client::prune::prune_history(
                        &rem,
                        &store,
                        &keyring,
                        &ref_name,
                        cfg.retention_keep_versions,
                        roster_seq,
                    )
                    .await
                    {
                        eprintln!("history prune skipped: {e}");
                    }
                }
            }
            // A cas-head conflict is a normal concurrent-write race (another device advanced the ref
            // while we were pushing), not an error — re-sync immediately to fetch its head and merge.
            Err(secsec_client::ClientError::CasConflict) => {
                retry_now = true;
            }
            // A head from a device we don't know: our roster may be stale. Refresh once and retry; if
            // it still fails right after a refresh, it is a genuine non-member (forged/revoked) head.
            Err(secsec_client::ClientError::HeadNotMember) => {
                if refolded {
                    eprintln!(
                        "sync error: fetched head signed by a non-member (after roster refresh)"
                    );
                } else {
                    want_refold = true;
                    retry_now = true;
                }
            }
            // A dead connection is healed by the reconnect at the top of the next iteration — don't
            // surface it as a sync error.
            Err(e) => {
                if conn.close_reason().is_none() {
                    eprintln!("sync error: {e}");
                }
            }
        }
        initial = false;
        if once && !retry_now {
            break;
        }
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

/// Re-establish a session after a dropped connection: dial the (already-pinned) server again and
/// redo the §11 handshake, returning the fresh endpoint + connection + session transcript.
async fn reconnect_session(
    addr: SocketAddr,
    host_id: [u8; 32],
    device: &DeviceKey,
    tuning: Tuning,
) -> Result<(quinn::Endpoint, quinn::Connection, [u8; 32]), Box<dyn Error>> {
    let (endpoint, conn, _host_id) = connect(addr, Some(host_id), tuning).await?;
    let sess = client_handshake(&conn, device, host_id, rand32()?).await?;
    Ok((endpoint, conn, sess.transcript))
}

// ---- invite ----

async fn run_invite(
    dir: PathBuf,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir)
        .ok_or("this folder isn't linked to a repo yet — run `secsec sync` on it first")?;
    let device = load_device(key, passphrase_stdin)?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id), Tuning::default()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, _st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;

    let (code, disp) = pair::new_invite()?;
    println!("INVITE CODE: {disp}");
    println!(
        "on the new device (add its key to the server's authorized_keys first):\n  secsec sync <dir> --server {} --invite {disp}",
        link.server
    );
    println!("waiting for the device to pair — Ctrl-C to cancel…");
    let enrolled = pair::run_host(
        &rem,
        &device,
        &mk,
        &link.rfp,
        &host_id,
        &code,
        PAIR_HOST_ROUNDS,
        unix_secs(),
    )
    .await?;
    println!("paired device {}", hex(&enrolled));
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

// ---- devices / revoke ----

/// List the repo's enrolled devices: a short device id, the device's SSH key fingerprint (the
/// `SHA256:…` string `ssh-keygen -lf` prints, so you can match it to a physical device), and a marker
/// for the current device.
async fn run_devices(
    dir: PathBuf,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or("this folder isn't linked to a repo yet")?;
    let device = load_device(key, passphrase_stdin)?;
    let me = device.device_id()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id), Tuning::default()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (_mk, st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    println!("{} device(s) in this repo:", st.members.len());
    for (id, pubkey) in &st.members {
        let fp = pubkey
            .ssh_fingerprint()
            .unwrap_or_else(|_| "<unknown>".to_string());
        let mark = if *id == me { "  ← this device" } else { "" };
        println!("  {}  {}{}", &hex(id)[..12], fp, mark);
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

/// Print the server host fingerprint this folder pinned (TOFU, §11) — the same `host pin` the
/// server prints on startup, for **out-of-band** comparison. Offline: reads the local link only.
fn run_hostpin(dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or("this folder isn't linked to a repo yet")?;
    println!("server:   {}", link.server);
    println!("host pin: {}", hex(&link.host_id));
    println!(
        "compare this to the `host pin` printed by `secsec serve` on the server (out-of-band)."
    );
    Ok(())
}

// ---- log / restore (history) ----

/// A repo-relative path: drop empty / `.` segments and reject `..` (no escaping the synced folder).
fn normalize_repo_path(p: &str) -> Result<String, Box<dyn Error>> {
    let comps: Vec<&str> = p
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if comps.contains(&"..") {
        return Err("path must be inside the synced folder (no '..')".into());
    }
    Ok(comps.join("/"))
}

/// Human-friendly age of an advisory commit timestamp (§10: `ts` is a hint, not trusted for security).
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

fn print_log_entry(e: &secsec_client::history::LogEntry, now: u64) {
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
        "{}  {:<9}  dev {}{}  {}",
        &hex(&e.commit_id)[..12],
        rel_time(e.ts, now),
        &hex(&e.device_id)[..8],
        merge,
        changed
    );
}

fn print_path_version(v: &secsec_client::history::PathVersion, now: u64) {
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

/// `secsec log [path]` — the repo's change history, or one file/folder's version history. Run inside
/// the synced folder. Reads history over the wire into a throwaway store (the shared object cache may
/// be held by a running `sync`), so it works alongside a live sync.
async fn run_log(
    path: Option<String>,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = std::env::current_dir()?;
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or(
        "not inside a synced folder — run `secsec log` in a folder you've `secsec sync`-ed",
    )?;
    let path = path.map(|p| normalize_repo_path(&p)).transpose()?;

    let device = load_device(key, passphrase_stdin)?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id), Tuning::default()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, _st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    let keyring = data_keyring_remote(&rem, &mk).await?;

    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let now = unix_secs();
    match secsec_client::fetch_head(&rem, &keyring, &link.ref_name).await? {
        None => println!(
            "no history yet — nothing has been synced to '{}'.",
            link.ref_name
        ),
        Some((head, _sig, _blob)) => {
            secsec_client::history::fetch_history(&rem, &store, &keyring, &head.commit_id).await?;
            match &path {
                None => {
                    let log = secsec_client::history::repo_log(&keyring, &store, &head.commit_id)?;
                    for e in &log {
                        print_log_entry(e, now);
                    }
                    println!("{} commit(s).", log.len());
                }
                Some(p) => {
                    let hist =
                        secsec_client::history::path_history(&keyring, &store, &head.commit_id, p)?;
                    if hist.is_empty() {
                        println!("no history for '{p}' (it may not exist in the repo).");
                    } else {
                        for v in &hist {
                            print_path_version(v, now);
                        }
                        println!("{} version(s) of '{p}'.", hist.len());
                    }
                }
            }
        }
    }
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

/// `secsec restore <path> [version]` — write a historic version of a file/folder into the working
/// folder. With no version, restores the *previous* version of that path. The change then propagates
/// via the normal sync (a running `secsec sync` picks it up), exactly like copying an old file over.
async fn run_restore(
    path: String,
    version: Option<String>,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = std::env::current_dir()?;
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or(
        "not inside a synced folder — run `secsec restore` in a folder you've `secsec sync`-ed",
    )?;
    let path = normalize_repo_path(&path)?;
    if path.is_empty() {
        return Err("specify a file or folder to restore".into());
    }

    let device = load_device(key, passphrase_stdin)?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id), Tuning::default()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, _st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    let keyring = data_keyring_remote(&rem, &mk).await?;

    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let head = secsec_client::fetch_head(&rem, &keyring, &link.ref_name)
        .await?
        .ok_or("no history yet — nothing to restore")?
        .0;
    secsec_client::history::fetch_history(&rem, &store, &keyring, &head.commit_id).await?;

    let target = match version {
        Some(prefix) => {
            let prefix = prefix.to_lowercase();
            let ids = secsec_client::history::commit_ids(&keyring, &store, &head.commit_id)?;
            let matches: Vec<[u8; 32]> = ids
                .into_iter()
                .filter(|c| hex(c).starts_with(&prefix))
                .collect();
            match matches.as_slice() {
                [c] => *c,
                [] => return Err(format!("no commit matches '{prefix}' — see `secsec log`").into()),
                _ => {
                    return Err(format!(
                        "'{prefix}' matches more than one commit — use a longer prefix"
                    )
                    .into())
                }
            }
        }
        None => {
            let hist =
                secsec_client::history::path_history(&keyring, &store, &head.commit_id, &path)?;
            // Path gone from disk → bring back the most recent version where it existed
            // (undo-delete). Still present → "previous" = the one before the current content:
            // hist[0] is the current commit, hist[1] the version before it.
            let chosen = if dir.join(&path).exists() {
                hist.get(1).map(|v| v.commit_id)
            } else {
                hist.iter().find(|v| v.present).map(|v| v.commit_id)
            };
            chosen.ok_or_else(|| {
                format!("'{path}' has no earlier version in the history to restore.")
            })?
        }
    };

    secsec_client::history::restore(&rem, &store, &keyring, &target, &path, &dir).await?;
    println!(
        "restored '{path}' from commit {} — your running `secsec sync` will propagate it (or run `secsec sync`).",
        &hex(&target)[..12]
    );
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

/// Revoke a device by a (prefix of its) device id: rotate the master key away from it (and its
/// add-by closure) over the wire, so it can't decrypt anything written afterward. Also reminds the
/// operator to remove its key from the server's `authorized_keys`.
async fn run_revoke(
    device_prefix: String,
    dir: PathBuf,
    key: Option<PathBuf>,
    passphrase_stdin: bool,
) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or("this folder isn't linked to a repo yet")?;
    let device = load_device(key, passphrase_stdin)?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id), Tuning::default()).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;

    // Resolve the device-id prefix against the roster (must be unique).
    let prefix = device_prefix.to_lowercase();
    let matches: Vec<_> = st
        .members
        .keys()
        .filter(|id| hex(&id[..]).starts_with(&prefix))
        .collect();
    let target = match matches.as_slice() {
        [id] => **id,
        [] => return Err(format!("no enrolled device matches '{device_prefix}'").into()),
        _ => {
            return Err(format!(
                "'{device_prefix}' matches more than one device — use a longer prefix"
            )
            .into())
        }
    };
    if target == device.device_id()? {
        return Err("refusing to revoke the device you're running this from".into());
    }

    secsec_client::repo::rotate_repo_remote(
        &rem,
        &device,
        &mk,
        &st,
        &link.rfp,
        Some(target),
        unix_secs(),
    )
    .await?;
    println!(
        "revoked device {} — rotated to a new key generation",
        hex(&target)
    );
    println!(
        "now remove its public key from the server's ~/.ssh/authorized_keys so it can't reconnect."
    );
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

// ---- reset ----

/// `secsec reset [dir]` — remove all secsec-owned state at a location, **without** touching your
/// files or your `~/.ssh` key: the folder's out-of-tree client sync state, and/or a serve dir's
/// `repo.secsec` + `hostkey/`. Prompts with the exact paths before deleting (`--yes` skips). The
/// next `sync` re-clones as a fresh device; the next `serve` mints a new host key (clients re-TOFU).
fn run_reset(dir: PathBuf, yes: bool) -> Result<(), Box<dyn Error>> {
    // (path, what-it-is, is_dir) for each piece of secsec state that actually exists at `dir`.
    let mut targets: Vec<(PathBuf, &str, bool)> = Vec::new();

    // Client state: keyed by the folder's canonical path (must match `state_dir_for`). Check the
    // current root and the pre-consolidation location, so `reset` fully cleans either.
    if let Ok(abs) = std::fs::canonicalize(&dir) {
        let name = hex(blake3::hash(abs.to_string_lossy().as_bytes()).as_bytes());
        let candidates = [
            config_root()?.join("folders").join(&name),
            home()?.join(".local/state/secsec").join(&name),
        ];
        for cdir in candidates {
            if cdir.exists() {
                targets.push((
                    cdir,
                    "client sync state — link, object cache, rollback cursor",
                    true,
                ));
            }
        }
    }
    // Server state: lives directly in the serve dir (which holds nothing but these).
    let repo = dir.join("repo.secsec");
    if repo.is_file() {
        targets.push((
            repo,
            "server repository — the ENTIRE encrypted store (all devices' data)",
            false,
        ));
    }
    let hostkey = dir.join("hostkey");
    if hostkey.is_dir() {
        targets.push((
            hostkey,
            "server host key — clients will have to re-verify the pin",
            true,
        ));
    }

    if targets.is_empty() {
        println!(
            "nothing to reset — no secsec state found at {}",
            dir.display()
        );
        return Ok(());
    }

    println!("This will permanently remove:");
    for (path, what, _) in &targets {
        println!("  {}\n      {what}", path.display());
    }
    println!("Your files and your ~/.ssh key are left untouched.");

    if !yes {
        use std::io::Write;
        eprint!("Proceed? [y/N] ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES") {
            println!("aborted — nothing removed.");
            return Ok(());
        }
    }

    for (path, _, is_dir) in &targets {
        if *is_dir {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        println!("removed {}", path.display());
    }
    println!("reset complete.");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let rt = || tokio::runtime::Runtime::new();
    let cwd = || PathBuf::from(".");
    match cli.cmd {
        Cmd::Serve { dir, port } => rt()?.block_on(run_serve(dir.unwrap_or_else(cwd), port)),
        Cmd::Sync {
            dir,
            server,
            invite,
            once,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_sync(
            dir.unwrap_or_else(cwd),
            server,
            invite,
            once,
            key,
            passphrase_stdin,
        )),
        Cmd::Invite {
            dir,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_invite(dir.unwrap_or_else(cwd), key, passphrase_stdin)),
        Cmd::Devices {
            dir,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_devices(dir.unwrap_or_else(cwd), key, passphrase_stdin)),
        // hostpin is offline (reads the local link), so it needs no tokio runtime.
        Cmd::Hostpin { dir } => run_hostpin(dir.unwrap_or_else(cwd)),
        Cmd::Log {
            path,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_log(path, key, passphrase_stdin)),
        Cmd::Restore {
            path,
            version,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_restore(path, version, key, passphrase_stdin)),
        Cmd::Revoke {
            device,
            dir,
            key,
            passphrase_stdin,
        } => rt()?.block_on(run_revoke(
            device,
            dir.unwrap_or_else(cwd),
            key,
            passphrase_stdin,
        )),
        // reset is pure filesystem cleanup (no network), so it needs no tokio runtime.
        Cmd::Reset { dir, yes } => run_reset(dir.unwrap_or_else(cwd), yes),
    }
}
