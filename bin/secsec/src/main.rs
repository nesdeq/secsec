//! `secsec` — the CLI binary (`finaldesign.md` §11, §12).
//!
//! Subcommands: `init` (repository genesis — §7), `serve` (the blind server), `hostkey` (host-pin
//! helper), and `sync` (cold-start over the wire, then reconcile a working dir with a ref — §8.1/§10).
//! `init` writes the genesis roster + this device's keyslot and prints the RFP; `serve` is the blind
//! server (signs §15 receipts with its host receipt key); `sync` recovers the master key + roster from
//! the remote, snapshots the dir, and clones/publishes/pulls/merges, optionally `--watch`-ing for
//! continuous live sync. The host is pinned by `--host-cert` (full cert) or `--host-fp` (fingerprint).

#![allow(missing_docs)] // a binary crate exports no public API

use clap::{Parser, Subcommand};
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{init_repo, open_repo_remote};
use secsec_client::sync::sync_once;
use secsec_client::{load_frontier, save_frontier, FrontierLoad};
use secsec_server::serve::serve_connection;
use secsec_server::Server;
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_sync::rollback::SyncFrontier;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{client_config, server_config};
use secsec_transport::HostPin;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default listen address (§19: udp/8899, overridable).
const DEFAULT_LISTEN: &str = "0.0.0.0:8899";

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
    /// Initialize a new repository (device 1): write the genesis roster + this device's keyslot into
    /// the store and print the RFP anchor to record out-of-band (§7).
    Init {
        /// Path to the redb store to initialize (created if absent).
        #[arg(long)]
        store: PathBuf,
        /// Path to this device's OpenSSH **private** key (Ed25519).
        #[arg(long)]
        key: PathBuf,
    },
    /// Run the blind sync server.
    Serve {
        /// Path to the redb object store (created if absent).
        #[arg(long)]
        store: PathBuf,
        /// Directory holding the self-signed host key (generated on first run).
        #[arg(long)]
        hostkey_dir: PathBuf,
        /// UDP address to listen on.
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: SocketAddr,
    },
    /// Print the server's host pin (the `host_id` clients pin via `--host-fp`), generating the host
    /// key if absent.
    Hostkey {
        /// Directory holding the self-signed host key.
        #[arg(long)]
        hostkey_dir: PathBuf,
    },
    /// Sync a working directory with a remote ref once (cold-start over the wire, then reconcile).
    Sync {
        /// Server address (e.g. `127.0.0.1:8899`).
        #[arg(long)]
        remote: SocketAddr,
        /// The server's host certificate (DER), e.g. `<hostkey_dir>/hostkey.crt`. Pins the host by its
        /// full key. Mutually exclusive with `--host-fp`.
        #[arg(long, conflicts_with = "host_fp", required_unless_present = "host_fp")]
        host_cert: Option<PathBuf>,
        /// The server's host fingerprint (`host_id` hex, from `secsec hostkey`) — pin by fingerprint
        /// alone, no cert needed (§11). Mutually exclusive with `--host-cert`.
        #[arg(long)]
        host_fp: Option<String>,
        /// This device's OpenSSH private key (the one enrolled at `init`).
        #[arg(long)]
        key: PathBuf,
        /// The working directory to sync.
        #[arg(long)]
        dir: PathBuf,
        /// The local object store (created if absent).
        #[arg(long)]
        store: PathBuf,
        /// Directory holding local sync state (sealed frontier + base cursor).
        #[arg(long)]
        state: PathBuf,
        /// The repository fingerprint (RFP) hex from `init` — the out-of-band trust anchor.
        #[arg(long)]
        rfp: String,
        /// The ref name to sync.
        #[arg(long, default_value = "main")]
        r#ref: String,
        /// Keep running: re-sync on every debounced filesystem change and on a periodic remote poll
        /// (continuous live sync, §10).
        #[arg(long)]
        watch: bool,
        /// Debounce window for coalescing a burst of file changes into one sync, in milliseconds.
        /// (Snapshot cadence is config, §19; this is the overridable default.)
        #[arg(long, default_value_t = 1000)]
        debounce_ms: u64,
        /// In `--watch` mode, also poll the remote this often (seconds) to pick up other devices'
        /// pushes. Overridable; mirrors the §19 keepalive-scale cadence.
        #[arg(long, default_value_t = 15)]
        poll_secs: u64,
    },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the persisted self-signed host key from `dir`, generating + persisting one on first run
/// (TOFU host identity, §11). Returns `(cert_der, key_der)`.
fn load_or_generate_hostkey(dir: &Path) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let cert_path = dir.join("hostkey.crt");
    let key_path = dir.join("hostkey.key");
    if cert_path.exists() && key_path.exists() {
        return Ok((std::fs::read(cert_path)?, std::fs::read(key_path)?));
    }
    let ck = rcgen::generate_simple_self_signed(vec!["secsec.invalid".to_string()])?;
    let cert = ck.cert.der().to_vec();
    let key = ck.key_pair.serialize_der();
    std::fs::create_dir_all(dir)?;
    std::fs::write(&cert_path, &cert)?;
    std::fs::write(&key_path, &key)?;
    Ok((cert, key))
}

/// Load-or-generate the host's 32-byte Ed25519 receipt-key seed (§15 signed receipts), persisted at
/// `<dir>/hostkey.receipt`.
fn load_or_generate_receipt_key(dir: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    let path = dir.join("hostkey.receipt");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes.try_into().expect("checked len"));
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, seed)?;
    Ok(seed)
}

async fn run_serve(
    store: PathBuf,
    hostkey_dir: PathBuf,
    listen: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let (cert, key) = load_or_generate_hostkey(&hostkey_dir)?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    let receipt_seed = load_or_generate_receipt_key(&hostkey_dir)?;
    let store = Store::open(store)?;
    // Shared via Arc; the store is lock-free (redb-transactional) and only the small replay/rate-limit
    // state is briefly locked inside handle(), so connections are served CONCURRENTLY. Signed §15
    // receipts are enabled with the host receipt key + host_id.
    let server = std::sync::Arc::new(Server::new(store).with_receipts(&receipt_seed, host_id));

    let endpoint = quinn::Endpoint::server(server_config(&cert, &key)?, listen)?;
    println!("secsec serve — host pin {}", hex(&host_id));
    println!("listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let server = server.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("accept failed: {e}");
                    return;
                }
            };
            if let Err(e) = serve_connection(&conn, &server, host_id, unix_secs).await {
                eprintln!("connection closed: {e}");
            }
        });
    }
    Ok(())
}

fn run_init(store: PathBuf, key: PathBuf) -> Result<(), Box<dyn Error>> {
    let pem = std::fs::read_to_string(&key)?;
    let device = DeviceKey::from_openssh(&pem)?;
    let store = Store::open(store)?;
    let rfp = init_repo(&store, &device, unix_secs())?;
    println!(
        "repository initialized for device {}",
        hex(&device.device_id()?)
    );
    // RFP = BLAKE3(canonical(genesis)) (§5) — labeled as such, NOT "SHA256:", so an out-of-band
    // fingerprint comparison uses the right algorithm.
    println!(
        "RFP (BLAKE3; record this out-of-band, share at every enrollment): {}",
        hex(&rfp)
    );
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid hex")?;
    bytes
        .try_into()
        .map_err(|_| "expected 32 bytes (64 hex chars)".into())
}

/// The last-synced base cursor is a commit **content hash** (not secret — the server already stores
/// objects by id), so it is persisted as plain hex; the anti-rollback frontier beside it IS sealed.
fn read_base(path: &Path) -> Result<Option<[u8; 32]>, Box<dyn Error>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(parse_hex32(s.trim())?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_sync(
    remote: SocketAddr,
    host_cert: Option<PathBuf>,
    host_fp: Option<String>,
    key: PathBuf,
    dir: PathBuf,
    store_path: PathBuf,
    state: PathBuf,
    rfp_hex: String,
    ref_name: String,
    watch: bool,
    debounce_ms: u64,
    poll_secs: u64,
) -> Result<(), Box<dyn Error>> {
    use std::time::Duration;

    let device = DeviceKey::from_openssh(&std::fs::read_to_string(&key)?)?;
    // Pin by full cert (--host-cert) or by host_id fingerprint (--host-fp); clap guarantees one.
    let pin = match (host_cert, host_fp) {
        (Some(cert), _) => HostPin::from_cert(&std::fs::read(&cert)?)?,
        (None, Some(fp)) => HostPin::from_host_id(parse_hex32(&fp)?),
        (None, None) => return Err("one of --host-cert / --host-fp is required".into()),
    };
    let host_id = pin.host_id();
    let rfp = parse_hex32(&rfp_hex)?;

    // connect + §11 handshake.
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config(pin)?);
    let conn = endpoint.connect(remote, "secsec.invalid")?.await?;
    let mut client_nonce = [0u8; 32];
    getrandom::fill(&mut client_nonce)?;
    let sess = client_handshake(&conn, &device, host_id, client_nonce).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);

    // cold-start: recover the master key + roster over the wire, anchored to the RFP.
    let (mk, st) = open_repo_remote(&rem, &device, &rfp).await?;

    // local state.
    let store = Store::open(&store_path)?;
    std::fs::create_dir_all(&state)?;
    let frontier_path = state.join("frontier");
    let base_path = state.join("base");
    let mut frontier = match load_frontier(&frontier_path, &device)? {
        FrontierLoad::Loaded(f) => f,
        FrontierLoad::Absent => SyncFrontier::default(),
    };
    let mut base = read_base(&base_path)?;

    // In --watch mode, a background thread feeds debounced file-change ticks; a periodic timer feeds
    // remote-poll ticks (to pick up other devices' pushes). Either triggers a re-sync.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    if watch {
        let wdir = dir.clone();
        std::thread::spawn(move || {
            let _ = secsec_client::watcher::watch_dir(
                &wdir,
                Duration::from_millis(debounce_ms),
                || tx.send(()).is_ok(),
            );
        });
        println!(
            "watching {} (debounce {debounce_ms}ms, poll {poll_secs}s) — Ctrl-C to stop",
            dir.display()
        );
    }
    let mut poll = tokio::time::interval(Duration::from_secs(poll_secs.max(1)));
    poll.tick().await; // consume the immediate first tick

    let mut initial = true;
    loop {
        if !initial {
            // Wait for a file-change or poll tick (watch mode only; one-shot breaks below).
            tokio::select! {
                ev = rx.recv() => { if ev.is_none() { break; } }
                _ = poll.tick() => {}
            }
        }
        // genesis-generation repos sit at roster_seq 0 (rotation-era sync is a later milestone).
        match sync_once(
            &rem,
            &store,
            &dir,
            &mk,
            &device,
            &st.members,
            &frontier,
            &ref_name,
            0,
            base,
            unix_secs(),
        )
        .await
        {
            Ok(outcome) => {
                save_frontier(&frontier_path, &outcome.frontier, &device)?;
                if let Some(b) = outcome.base {
                    std::fs::write(&base_path, hex(&b))?;
                }
                // Quiet on a no-op poll; report real work and the first sync.
                if initial || !matches!(outcome.kind, secsec_client::sync::SyncKind::UpToDate) {
                    println!("sync: {:?}", outcome.kind);
                }
                frontier = outcome.frontier;
                base = outcome.base;
            }
            Err(e) => eprintln!("sync error: {e}"),
        }
        initial = false;
        if !watch {
            break;
        }
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn run_hostkey(hostkey_dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let (cert, _key) = load_or_generate_hostkey(&hostkey_dir)?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    println!("host pin (give clients --host-fp): {}", hex(&host_id));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { store, key } => run_init(store, key),
        Cmd::Serve {
            store,
            hostkey_dir,
            listen,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_serve(store, hostkey_dir, listen))
        }
        Cmd::Hostkey { hostkey_dir } => run_hostkey(hostkey_dir),
        Cmd::Sync {
            remote,
            host_cert,
            host_fp,
            key,
            dir,
            store,
            state,
            rfp,
            r#ref,
            watch,
            debounce_ms,
            poll_secs,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_sync(
                remote,
                host_cert,
                host_fp,
                key,
                dir,
                store,
                state,
                rfp,
                r#ref,
                watch,
                debounce_ms,
                poll_secs,
            ))
        }
    }
}
