//! Mechanical KAT vector check (`secsec-Design.md` §3): compute every value in
//! `vectors/secsec-kat-v1.txt` from the **live code paths** and compare against the committed file, so
//! the human/cross-impl export can never drift from the implementation.

use secsec_frame::{Frame, ObjType};
use secsec_kdf::{obj_key, roster_entry_key, roster_keyhist_key, MasterKey};
use secsec_roster::{seal_entry, seal_roster_keyhist};
use secsec_sync::{ref_hash, seal_head, Head};
use secsec_transport::auth::SessionTranscript;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Compute every named vector from live code — keyed by the exact name used in the committed file.
fn computed() -> BTreeMap<String, String> {
    let mut v: BTreeMap<String, String> = BTreeMap::new();
    let mut put = |k: &str, val: String| {
        v.insert(k.to_string(), val);
    };

    // [kdf] — master_key = 0x11*32, gen 1.
    let mk = MasterKey::new(1, [0x11; 32]);
    let rk = mk.roster_key();
    put("enc_key[g=1][t=0]", hx(&mk.enc_key(0)[..]));
    put("id_key[g=1][t=0]", hx(&mk.id_key(0)[..]));
    put("cdc_seed[g=1]", hx(&mk.cdc_seed()[..]));
    put("head_key[g=1]", hx(&mk.head_key()[..]));
    put("roster_key[g=1]", hx(&rk[..]));
    put("ref_name_key", hx(&mk.ref_name_key()[..]));
    put("mk_commit[g=1]", hx(&mk.mk_commit()));
    put(
        "obj_key(roster_key[g=1], id)",
        hx(&obj_key(&rk, &[0x22; 32])[..]),
    );
    put(
        "roster_entry_key(roster_key[g=1], 1)",
        hx(&roster_entry_key(&rk, 1)[..]),
    );
    put(
        "roster_keyhist_key(roster_key[g=1], 1)",
        hx(&roster_keyhist_key(&rk, 1)[..]),
    );

    // [frame]
    put(
        "frame.v1(gen=1, type=Chunk)",
        hx(&Frame::v1(1, ObjType::Chunk).encode()),
    );

    // [aead] — CTX seal.
    let (ctx_tag, ct) = secsec_aead::seal(
        &[0x42; 32],
        b"secsec-aead-kat-ad",
        b"secsec aead kat plaintext",
    );
    put("ctx_tag", hx(&ctx_tag));
    put("ciphertext", hx(&ct));

    // [object] — content id + stored blob.
    let (cid, blob) =
        secsec_object::seal_object(&mk, ObjType::Chunk, &[0x01; 16], b"object-plane-kat");
    put("content_id", hx(&cid));
    put("blob", hx(&blob));

    // [head] — ref hash + sealed head blob (fixed nonce to pin the wire format).
    let rnk = mk.ref_name_key();
    put("ref_hash", hx(&ref_hash(&rnk, "main")));
    let head = Head {
        ref_name: "main".to_string(),
        commit_id: [0xC0; 32],
        head_version: 3,
        roster_seq: 5,
        prev_head: [0xB0; 32],
    };
    put(
        "head_blob",
        hx(&seal_head(&mk, &rnk, &head, b"dummy-sig", &[0x07; 12])),
    );

    // [auth] — session transcript.
    let mut t = SessionTranscript::new();
    t.client_hello(1, &[1; 32])
        .server_hello(1, &[2; 32], &[3; 32]);
    put("session_transcript", hx(&t.finalize()));

    // [roster] — per-entry AEAD + roster-key history wrap.
    put(
        "roster_entry.blob",
        hx(&seal_entry(&rk, 1, 1, b"roster-entry-kat")),
    );
    let mut rkg = [0u8; 32];
    for (i, b) in rkg.iter_mut().enumerate() {
        *b = i as u8; // 0x00..0x1f
    }
    put(
        "roster_keyhist.wrap",
        hx(&seal_roster_keyhist(&rk, 1, &rkg)),
    );

    v
}

/// Parse `name = value` lines from the committed vectors file (stripping trailing `# comments`).
fn parse_file(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        // The assignment `=` is space-preceded (column alignment); an in-name `=` like `[g=1]` is not.
        // Split on the first " =" so names containing `=` parse correctly.
        let Some((name, rest)) = line.split_once(" =") else {
            continue;
        };
        // strip a trailing comment, then trim.
        let value = rest.split('#').next().unwrap_or("").trim().to_string();
        m.insert(name.trim().to_string(), value);
    }
    m
}

/// Path to `vectors/secsec-kat-v1.txt` relative to the workspace root.
fn vectors_path() -> PathBuf {
    // xtask runs from the workspace root under `cargo xtask`.
    PathBuf::from("vectors/secsec-kat-v1.txt")
}

/// Compute all vectors from live code and compare to the committed file. `check` only reports; without
/// it, also print the computed values (for a human updating the file after a deliberate change).
pub fn run(check: bool) -> Result<(), String> {
    let computed = computed();
    let path = vectors_path();
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let file = parse_file(&text);

    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for (name, val) in &computed {
        match file.get(name) {
            Some(f) if f == val => {}
            Some(f) => mismatches.push(format!("  {name}\n    file: {f}\n    code: {val}")),
            None => missing.push(name.clone()),
        }
    }

    if !check {
        println!("# computed from live code ({} vectors):", computed.len());
        for (k, v) in &computed {
            println!("{k} = {v}");
        }
    }

    if !mismatches.is_empty() || !missing.is_empty() {
        let mut msg = String::new();
        if !mismatches.is_empty() {
            msg.push_str(&format!(
                "{} vector(s) DIFFER from the committed file:\n{}\n",
                mismatches.len(),
                mismatches.join("\n")
            ));
        }
        if !missing.is_empty() {
            msg.push_str(&format!(
                "{} computed vector(s) absent from the file: {}\n",
                missing.len(),
                missing.join(", ")
            ));
        }
        return Err(msg);
    }

    println!(
        "vectors: all {} live-computed values match {} ✓",
        computed.len(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CI guard: every live-computed vector matches the committed file (the anti-drift check, run as a
    /// normal test so it can't be forgotten). Resolves the file relative to the workspace root.
    #[test]
    fn committed_vectors_match_live_code() {
        let computed = computed();
        // CARGO_MANIFEST_DIR is xtask/; the vectors file is ../vectors/.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/secsec-kat-v1.txt");
        let text = std::fs::read_to_string(&path).expect("read vectors file");
        let file = parse_file(&text);
        for (name, val) in &computed {
            assert_eq!(
                file.get(name).map(String::as_str),
                Some(val.as_str()),
                "vector `{name}` drifted: file vs live code"
            );
        }
    }
}
