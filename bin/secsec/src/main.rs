//! `secsec` — the CLI binary (`finaldesign.md` §11, §12).
//!
//! Subcommands: `init` (repository genesis — §7), `serve` (the blind server), and `hostkey` (host-pin
//! helper). `init` writes the genesis roster + this device's keyslot into a store and prints the RFP;
//! `serve` is fully functional (the server is blind — no master key). The remaining client subcommand
//! `sync` (cold-start over a remote + watcher-driven commit) needs the remote roster/keyslot read ops
//! and is the next milestone.

#![allow(missing_docs)] // a binary crate exports no public API

use clap::{Parser, Subcommand};
use secsec_client::repo::init_repo;
use secsec_server::serve::serve_connection;
use secsec_server::Server;
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_transport::quic::server_config;
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

async fn run_serve(
    store: PathBuf,
    hostkey_dir: PathBuf,
    listen: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let (cert, key) = load_or_generate_hostkey(&hostkey_dir)?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    let store = Store::open(store)?;
    let mut server = Server::new(store);

    let endpoint = quinn::Endpoint::server(server_config(&cert, &key)?, listen)?;
    println!("secsec serve — host pin {}", hex(&host_id));
    println!("listening on {}", endpoint.local_addr()?);

    // Serve connections sequentially (one at a time) — the shared Server state (nonce store, rate
    // limiters) is single-owner; concurrent serving would wrap it in a lock. A skeleton limitation.
    while let Some(incoming) = endpoint.accept().await {
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        if let Err(e) = serve_connection(&conn, &mut server, host_id, unix_secs()).await {
            eprintln!("connection closed: {e}");
        }
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
    }
}
