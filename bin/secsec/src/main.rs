//! `secsec` — the CLI binary (`finaldesign.md` §11, §12).
//!
//! This skeleton ships the **server** side (`serve`) and a host-key helper (`hostkey`). The server is
//! blind — it needs no master key, only a self-signed host identity and a store — so it is fully
//! functional today. The client subcommands (`init` / `sync`) depend on the §7 enrollment flow
//! (master-key genesis + keyslot), which is the next milestone, and are intentionally not stubbed in
//! with fake key material.

#![allow(missing_docs)] // a binary crate exports no public API

use clap::{Parser, Subcommand};
use secsec_server::serve::serve_connection;
use secsec_server::Server;
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

fn run_hostkey(hostkey_dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let (cert, _key) = load_or_generate_hostkey(&hostkey_dir)?;
    let host_id = HostPin::from_cert(&cert)?.host_id();
    println!("host pin (give clients --host-fp): {}", hex(&host_id));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.cmd {
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
