//! `secsec` — the CLI binary (`secsec-Design.md` §11, §12).
//!
//! Two everyday commands and one onboarding command:
//! - `secsec serve [dir] [port]` — the blind server. Reads the operator's `~/.ssh/authorized_keys` as a
//!   **mandatory** connection gate (re-read per connection); stores ciphertext under `dir`; defaults to
//!   the current dir and udp/8899. The repository is created lazily by the first authorized device.
//! - `secsec sync <dir> [--server host[:port]] [--invite code] [--name ref]` — link a folder to a repo
//!   and keep it in continuous two-way sync. Name the server once (first device creates the repo;
//!   joining devices pass `--invite`); afterwards just `secsec sync <dir>`. Uses `~/.ssh/id_ed25519`.
//! - `secsec invite <dir>` — on an enrolled device, print a one-time code and complete the pairing of a
//!   new device over the wire.
//! - `secsec devices <dir>` / `secsec revoke <device> <dir>` — list enrolled devices (with SSH
//!   fingerprints) and revoke one over the wire (§8.4: rotate the key away from a stolen device).
//! - `secsec hostpin <dir>` — print the server host fingerprint this folder pinned, to compare
//!   out-of-band against the `host pin` the server prints on startup (§11 TOFU verification).
//! - `secsec log [path]` / `secsec restore <path> [version]` — browse the change history (whole repo
//!   or one file/folder) and restore a historic version into the working folder, which the next sync
//!   propagates like any edit. Run inside the synced folder; read-side over the existing object plane.
//! - `secsec reset [dir]` — wipe secsec's local state where it is run (the client link/cache for a
//!   synced folder and/or a blind server's repo + host key in a serve dir), leaving your files and
//!   your `~/.ssh` key untouched. Start-over button after a botched link or for decommissioning.
//!
//! Garbage collection (§15) runs automatically inside `sync`; there is no manual command.

#![allow(missing_docs)] // a binary crate exports no public API

use clap::{Parser, Subcommand};
use secsec_client::pair;
use secsec_client::quic::QuicRemote;
use secsec_client::repo::{
    data_keyring_remote, fetch_roster_entries, init_repo_remote, open_repo_remote, RepoError,
    RosterAnchor,
};
use secsec_client::sync::sync_once;
use secsec_client::{load_frontier, save_frontier, FrontierLoad};
use secsec_server::{serve::serve_connection, Server};
use secsec_sig::DeviceKey;
use secsec_store::Store;
use secsec_sync::rollback::SyncFrontier;
use secsec_transport::handshake::client_handshake;
use secsec_transport::quic::{client_config, client_config_tofu, server_config};
use secsec_transport::HostPin;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// Default listen port (§19: udp/8899).
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
        /// The ref name for this folder (default: "main", so differently-named folders converge).
        /// Same name = same content across devices; use distinct names to keep several folders in one repo.
        #[arg(long)]
        name: Option<String>,
        /// Sync once and exit (default is to keep running and watch for changes).
        #[arg(long)]
        once: bool,
    },
    /// On an enrolled device, print a one-time invite code and pair a new device over the wire.
    Invite {
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
    },
    /// List the devices enrolled in a linked folder's repo (with their SSH key fingerprints).
    Devices {
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
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
    },
    /// Restore a historic version of a file/folder into the working folder; the next sync propagates it
    /// to other devices (like copying the old file over the current one). Run inside the synced folder.
    Restore {
        /// The file or folder within the repo to restore (relative to the synced folder root).
        path: String,
        /// The version: a commit-id prefix from `secsec log <path>`. Omit for the previous version.
        version: Option<String>,
    },
    /// Revoke a device (e.g. a stolen one): rotate the key away from it so it can't read new data.
    Revoke {
        /// The device id (a unique prefix is enough) — from `secsec devices`.
        device: String,
        /// A folder already linked to the repo (default: current directory).
        dir: Option<PathBuf>,
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

fn home() -> Result<PathBuf, Box<dyn Error>> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

/// Load this device's SSH key from `~/.ssh/id_ed25519`. If the key is passphrase-encrypted, prompt
/// for the passphrase (no echo) and decrypt it in memory — secsec needs the raw key, not just an
/// agent, so the passphrase is required, but the on-disk key stays encrypted (see
/// [`DeviceKey::from_openssh_passphrase`]).
fn default_device() -> Result<DeviceKey, Box<dyn Error>> {
    let path = home()?.join(".ssh/id_ed25519");
    let pem = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read device key {}: {e}", path.display()))?;
    match DeviceKey::from_openssh(&pem) {
        Ok(device) => Ok(device),
        Err(secsec_sig::SigError::Encrypted) => decrypt_device(&pem, &path),
        Err(e) => Err(e.into()),
    }
}

/// The device key is passphrase-encrypted: prompt on the terminal with no echo (up to 3 attempts) and
/// decrypt it in RAM. The typed passphrase is zeroized after each try and the on-disk key is never
/// modified.
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

/// The out-of-tree state directory for a synced folder: `~/.local/state/secsec/<hash(abspath)>/`
/// (created if absent). Holds the per-folder link, the sealed cursor, the receipt log, and the object
/// cache — so the synced folder itself stays nothing but the user's files.
fn state_dir_for(dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let abs = std::fs::canonicalize(dir)?;
    let h = blake3::hash(abs.to_string_lossy().as_bytes());
    let sdir = home()?.join(".local/state/secsec").join(hex(h.as_bytes()));
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

/// A folder's link to its repo (the git-remote analogue): server address, pinned host id, RFP anchor,
/// ref name, and the §8.1 sigchain anti-rollback anchor (`roster_seq` + tip hash, P7). Stored at
/// `<state>/link`; the synced folder stays clean. The anchor lives client-side so a malicious **server**
/// cannot roll the roster back (a disk-level rewrite is the §22 client-compromise residual).
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
    // None until the first successful cold-start records one (there is nothing to roll back against
    // on the very first open of a folder — the create/join itself establishes the anchor).
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
) -> Result<(quinn::Endpoint, quinn::Connection, [u8; 32]), Box<dyn Error>> {
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    let captured = match pinned {
        Some(h) => {
            ep.set_default_client_config(client_config(HostPin::from_host_id(h))?);
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

fn load_or_generate_receipt_key(dir: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    let path = dir.join("hostkey.receipt");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes.try_into().expect("checked len"));
        }
    }
    let seed = rand32()?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, seed)?;
    Ok(seed)
}

// ---- serve ----

async fn run_serve(dir: PathBuf, port: u16) -> Result<(), Box<dyn Error>> {
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
    let receipt_seed = load_or_generate_receipt_key(&hostkey_dir)?;
    let store = Store::open(&store_path)?;
    let server = std::sync::Arc::new(
        Server::new(store)
            .with_receipts(&receipt_seed, host_id)
            .with_authorized_file(auth_path.clone()), // re-read per connection (live add/remove)
    );

    let listen: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    let endpoint = quinn::Endpoint::server(server_config(&cert, &key)?, listen)?;
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
    while let Some(incoming) = endpoint.accept().await {
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
    name_opt: Option<String>,
    once: bool,
) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(&dir)?;
    let sdir = state_dir_for(&dir)?;
    let device = default_device()?;
    let link = read_link(&sdir);

    let server_str = server_opt
        .clone()
        .or_else(|| link.as_ref().map(|l| l.server.clone()))
        .ok_or("no server for this folder — pass --server host[:port] the first time")?;
    let addr = resolve_server(&server_str)?;
    // The ref defaults to "main", so two devices syncing their (locally differently-named) folders to
    // the same repo converge with zero flags. Use --name to keep several distinct folders in one repo.
    let ref_name = name_opt
        .or_else(|| link.as_ref().map(|l| l.ref_name.clone()))
        .unwrap_or_else(|| "main".to_string());

    // Connect: pin the saved host key, or TOFU on first contact.
    let pinned = link.as_ref().map(|l| l.host_id);
    let (mut endpoint, mut conn, host_id) = connect(addr, pinned).await?;
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
        // First device: attempt to create the repo. The genesis bootstrap is permitted only while the
        // roster is empty, so if the repo already exists this fails — and an unenrolled device must
        // instead join with an invite. (We can't pre-probe: reads require enrollment, which we don't
        // have yet.)
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
    let (mut mk, mut st, mut anchor) = open_repo_remote(&rem, &device, &rfp, prev_anchor).await?;
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
    let receipts_path = sdir.join("receipts");
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

    // Startup store hygiene, once per session — the local mirror of the server's §15 keep-everything
    // GC, so both ends prune identically: drop objects unreachable from our last-synced head (orphans
    // from cas-conflict retries / aborted pushes), keeping the full reachable history. Best-effort:
    // never blocks syncing. (This trims the logical object set; it does not shrink the redb file,
    // which redb re-grows to its working size on the next write — a real footprint cut needs §15+ work.)
    if let Some(b) = base {
        match secsec_client::gc::local_sweep(&keyring, &store, &b) {
            Ok(n) if n > 0 => eprintln!("local GC: dropped {n} unreachable object(s)"),
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
        std::thread::spawn(move || {
            let _ = secsec_client::watcher::watch_dir(&wdir, Duration::from_millis(1000), || {
                tx.send(()).is_ok()
            });
        });
        println!("watching {} — Ctrl-C to stop", dir.display());
    }
    let mut poll = tokio::time::interval(Duration::from_secs(15));
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

        // Self-heal a dropped connection instead of erroring on every later sync until the user restarts.
        if conn.close_reason().is_some() {
            eprintln!("connection lost — reconnecting to {server_str}…");
            match reconnect_session(addr, host_id, &device).await {
                Ok((ep, c, t)) => {
                    endpoint = ep;
                    conn = c;
                    transcript = t;
                    want_refold = true;
                }
                Err(err) => {
                    eprintln!("reconnect failed: {err}");
                    initial = false;
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
                    // Re-peel the data-key ring FIRST, so the roster update is all-or-nothing: never
                    // advance the generation (`mk`) without its matching keyring (which would make the
                    // current head/objects unreadable until the next tick). On a peel failure (e.g. a
                    // transient fetch glitch) keep the last-known roster and try again next cycle.
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
                            mk = m;
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
                // A genuine server rollback/reset: the fetched chain does not extend our persisted
                // anti-rollback anchor (P7). Only this is fatal; other roster-fold errors are treated as
                // transient below — a glitchy or partial fetch must not permanently stop syncing.
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

        match sync_once(
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
        )
        .await
        {
            Ok(outcome) => {
                save_frontier(&frontier_path, &outcome.frontier, &device)?;
                if let Some(b) = outcome.base {
                    std::fs::write(&base_path, hex(&b))?;
                }
                if !outcome.receipts.is_empty() {
                    let mut log = secsec_client::gc::parse_receipt_log(
                        &std::fs::read_to_string(&receipts_path).unwrap_or_default(),
                    );
                    secsec_client::gc::merge_receipts(&mut log, &outcome.receipts, unix_secs());
                    std::fs::write(
                        &receipts_path,
                        secsec_client::gc::serialize_receipt_log(&log),
                    )?;
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

                // Auto-GC once per session (best-effort, §15): prune server objects aged past the 48h
                // grace window so the store stays lean — the user never runs a gc command.
                if initial {
                    let gc = async {
                        if let Some((head, _, _)) =
                            secsec_client::fetch_head(&rem, &mk, &ref_name).await?
                        {
                            secsec_client::fetch_closure(&rem, &store, &keyring, &head.commit_id)
                                .await?;
                            let log = secsec_client::gc::parse_receipt_log(
                                &std::fs::read_to_string(&receipts_path).unwrap_or_default(),
                            );
                            let gc_gen = secsec_client::gc::gc_gen_from_log(&log, unix_secs());
                            if gc_gen != 0 {
                                let put_epoch = secsec_client::gc::put_epoch_from_log(&log);
                                let roster_seq =
                                    fetch_roster_entries(&rem).await?.len().saturating_sub(1)
                                        as u64;
                                secsec_client::gc::gc_collect(
                                    &rem,
                                    &store,
                                    &keyring,
                                    &[ref_name.as_str()],
                                    gc_gen,
                                    roster_seq,
                                    put_epoch,
                                )
                                .await?;
                            }
                        }
                        Ok::<(), Box<dyn Error>>(())
                    }
                    .await;
                    if let Err(e) = gc {
                        eprintln!("auto-gc skipped: {e}");
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
) -> Result<(quinn::Endpoint, quinn::Connection, [u8; 32]), Box<dyn Error>> {
    let (endpoint, conn, _host_id) = connect(addr, Some(host_id)).await?;
    let sess = client_handshake(&conn, device, host_id, rand32()?).await?;
    Ok((endpoint, conn, sess.transcript))
}

// ---- invite ----

async fn run_invite(dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir)
        .ok_or("this folder isn't linked to a repo yet — run `secsec sync` on it first")?;
    let device = default_device()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id)).await?;
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
async fn run_devices(dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or("this folder isn't linked to a repo yet")?;
    let device = default_device()?;
    let me = device.device_id()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id)).await?;
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

/// Print the server host fingerprint this folder pinned (TOFU, §11). It is `BLAKE3(SPKI)` of the
/// server's self-signed cert — the same value the server prints as `host pin` on startup — so an
/// operator can compare the two **out-of-band** to confirm there was no first-contact MITM. Offline:
/// it reads the pinned value from the folder's local link, it does not reach the server.
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
async fn run_log(path: Option<String>) -> Result<(), Box<dyn Error>> {
    let dir = std::env::current_dir()?;
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or(
        "not inside a synced folder — run `secsec log` in a folder you've `secsec sync`-ed",
    )?;
    let path = path.map(|p| normalize_repo_path(&p)).transpose()?;

    let device = default_device()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id)).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, _st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    let keyring = data_keyring_remote(&rem, &mk).await?;

    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let now = unix_secs();
    match secsec_client::fetch_head(&rem, &mk, &link.ref_name).await? {
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
async fn run_restore(path: String, version: Option<String>) -> Result<(), Box<dyn Error>> {
    let dir = std::env::current_dir()?;
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or(
        "not inside a synced folder — run `secsec restore` in a folder you've `secsec sync`-ed",
    )?;
    let path = normalize_repo_path(&path)?;
    if path.is_empty() {
        return Err("specify a file or folder to restore".into());
    }

    let device = default_device()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id)).await?;
    let sess = client_handshake(&conn, &device, host_id, rand32()?).await?;
    let rem = QuicRemote::new(&conn, sess.transcript, &device);
    let (mk, _st, _anchor) = open_repo_remote(&rem, &device, &link.rfp, link.anchor).await?;
    let keyring = data_keyring_remote(&rem, &mk).await?;

    let tmp = tempfile::tempdir()?;
    let store = Store::open(tmp.path().join("history.redb"))?;
    let head = secsec_client::fetch_head(&rem, &mk, &link.ref_name)
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
            // If the path is gone from disk (deleted), bring back the most recent version where it
            // existed — true undo-delete, whether or not the deletion has been synced yet. If it is
            // still present, "previous version" means the one before the current (undo the last edit):
            // history[0] is the current content's commit, history[1] the version before it.
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
async fn run_revoke(device_prefix: String, dir: PathBuf) -> Result<(), Box<dyn Error>> {
    let sdir = state_dir_for(&dir)?;
    let link = read_link(&sdir).ok_or("this folder isn't linked to a repo yet")?;
    let device = default_device()?;
    let addr = resolve_server(&link.server)?;
    let (endpoint, conn, host_id) = connect(addr, Some(link.host_id)).await?;
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

/// `secsec reset [dir]` — remove all secsec-owned state at a location and start clean, **without**
/// touching your files or your `~/.ssh` key. Deletes whichever of these exist here:
///   * the client sync state for the folder — the link, object cache, and rollback cursor, kept
///     out-of-tree under `~/.local/state/secsec/<hash>` (so the folder itself stays just your files);
///   * a blind server's `repo.secsec` (the whole encrypted store) and `hostkey/` (host + receipt key).
///
/// A synced folder yields only the first; a serve dir only the latter — they don't overlap. Prompts
/// with the exact paths before deleting (skip with `--yes`). Afterwards the next `sync` re-clones as a
/// fresh device, and the next `serve` mints a new host key (clients re-TOFU). Stop a running
/// sync/serve before resetting so it isn't operating on a store you just unlinked.
fn run_reset(dir: PathBuf, yes: bool) -> Result<(), Box<dyn Error>> {
    // (path, what-it-is, is_dir) for each piece of secsec state that actually exists at `dir`.
    let mut targets: Vec<(PathBuf, &str, bool)> = Vec::new();

    // Client state: out-of-tree, keyed by the folder's canonical path (must match `state_dir_for`).
    if let Ok(abs) = std::fs::canonicalize(&dir) {
        let h = blake3::hash(abs.to_string_lossy().as_bytes());
        let cdir = home()?.join(".local/state/secsec").join(hex(h.as_bytes()));
        if cdir.exists() {
            targets.push((
                cdir,
                "client sync state — link, object cache, rollback cursor",
                true,
            ));
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
            "server host key + receipt seed — clients will have to re-verify the pin",
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
        Cmd::Serve { dir, port } => rt()?.block_on(run_serve(
            dir.unwrap_or_else(cwd),
            port.unwrap_or(DEFAULT_PORT),
        )),
        Cmd::Sync {
            dir,
            server,
            invite,
            name,
            once,
        } => rt()?.block_on(run_sync(
            dir.unwrap_or_else(cwd),
            server,
            invite,
            name,
            once,
        )),
        Cmd::Invite { dir } => rt()?.block_on(run_invite(dir.unwrap_or_else(cwd))),
        Cmd::Devices { dir } => rt()?.block_on(run_devices(dir.unwrap_or_else(cwd))),
        // hostpin is offline (reads the local link), so it needs no tokio runtime.
        Cmd::Hostpin { dir } => run_hostpin(dir.unwrap_or_else(cwd)),
        Cmd::Log { path } => rt()?.block_on(run_log(path)),
        Cmd::Restore { path, version } => rt()?.block_on(run_restore(path, version)),
        Cmd::Revoke { device, dir } => rt()?.block_on(run_revoke(device, dir.unwrap_or_else(cwd))),
        // reset is pure filesystem cleanup (no network), so it needs no tokio runtime.
        Cmd::Reset { dir, yes } => run_reset(dir.unwrap_or_else(cwd), yes),
    }
}
