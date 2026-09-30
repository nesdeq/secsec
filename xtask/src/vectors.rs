//! The KAT anti-drift check (`secsec-Implementation.md` §3): every value in `vectors/secsec-kat-v1.txt` recomputed from live code.

use secsec_frame::{Frame, ObjType};
use secsec_kdf::{
    data_keyhist_key, obj_key, roster_entry_key, roster_entry_key_v2, roster_keyhist_key, MasterKey,
};
use secsec_roster::{seal_entry_v1, seal_entry_with_salt, seal_roster_keyhist};
use secsec_sync::{ref_hash, seal_head, Head};
use secsec_transport::auth::SessionTranscript;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Deterministic test bytes: `BLAKE3-XOF(label)` truncated to `len`.
fn xof(label: &str, len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(label.as_bytes());
    let mut v = vec![0u8; len];
    h.finalize_xof().fill(&mut v);
    v
}

/// Every computed vector, keyed `section/name` exactly as the committed file spells it.
fn computed() -> BTreeMap<String, String> {
    let mut v: BTreeMap<String, String> = BTreeMap::new();
    let mut put = |section: &str, name: &str, val: String| {
        v.insert(format!("{section}/{name}"), val);
    };

    let mk = MasterKey::new(1, [0x11; 32]);
    let rk = mk.roster_key();
    let salt = [0x5a; 32];
    put("kdf", "enc_key[g=1][t=0]", hx(&mk.enc_key(0)[..]));
    put("kdf", "id_key[g=1][t=0]", hx(&mk.id_key(0)[..]));
    put("kdf", "cdc_seed[g=1]", hx(&mk.cdc_seed()[..]));
    put("kdf", "head_key[g=1]", hx(&mk.head_key()[..]));
    put("kdf", "roster_key[g=1]", hx(&rk[..]));
    put("kdf", "ref_name_key", hx(&mk.ref_name_key()[..]));
    put("kdf", "mk_commit[g=1]", hx(&mk.mk_commit()));
    put(
        "kdf",
        "obj_key(roster_key[g=1], id)",
        hx(&obj_key(&rk, &[0x22; 32])[..]),
    );
    put(
        "kdf",
        "roster_entry_key(roster_key[g=1], 1)",
        hx(&roster_entry_key(&rk, 1)[..]),
    );
    put(
        "kdf",
        "roster_entry_key_v2(roster_key[g=1], 1, salt)",
        hx(&roster_entry_key_v2(&rk, 1, &salt)[..]),
    );
    put(
        "kdf",
        "roster_keyhist_key(roster_key[g=1], 1)",
        hx(&roster_keyhist_key(&rk, 1)[..]),
    );
    put(
        "kdf",
        "data_keyhist_key(master_key[g=1], 1)",
        hx(&data_keyhist_key(&[0x11; 32], 1)[..]),
    );

    put(
        "frame",
        "frame.v1(gen=1, type=Chunk)",
        hx(&Frame::v1(1, ObjType::Chunk).encode()),
    );
    put(
        "frame",
        "frame.v2(gen=1, type=RosterEntry)",
        hx(&Frame::v2(1, ObjType::RosterEntry).encode()),
    );

    let (ctx_tag, ct) = secsec_aead::seal(
        secsec_aead::UniqueKey::new(&[0x42; 32]),
        b"secsec-aead-kat-ad",
        b"secsec aead kat plaintext",
    );
    put("aead", "ctx_tag", hx(&ctx_tag));
    put("aead", "ciphertext", hx(&ct));

    let (cid, blob) =
        secsec_object::seal_object(&mk, ObjType::Chunk, &[0x01; 16], b"object-plane-kat");
    put("object", "content_id", hx(&cid));
    put("object", "blob", hx(&blob));

    let rnk = mk.ref_name_key();
    put("head", "ref_hash", hx(&ref_hash(&rnk, "main")));
    let head = Head {
        ref_name: "main".to_string(),
        commit_id: [0xC0; 32],
        head_version: 3,
        roster_seq: 5,
        prev_head: [0xB0; 32],
    };
    put(
        "head",
        "head_blob",
        hx(&seal_head(&mk, &rnk, &head, b"dummy-sig", &[0x07; 12])),
    );

    let mut t = SessionTranscript::new();
    t.client_hello(1, &[1; 32])
        .server_hello(1, &[2; 32], &[3; 32]);
    put("auth", "session_transcript", hx(&t.finalize()));

    put(
        "roster",
        "roster_entry.v1.blob",
        hx(&seal_entry_v1(&rk, 1, 1, b"roster-entry-kat")),
    );
    put(
        "roster",
        "roster_entry.v2.blob",
        hx(&seal_entry_with_salt(&rk, 1, 1, &salt, b"roster-entry-kat")),
    );
    let rkg: [u8; 32] = core::array::from_fn(|i| i as u8);
    put(
        "roster",
        "roster_keyhist.wrap",
        hx(&seal_roster_keyhist(&rk, 1, &rkg)),
    );

    let chunker = secsec_chunk::Chunker::with_defaults(&[0x33; 32]);
    let data = xof("secsec-chunk-kat", 1024 * 1024);
    let mut end = 0usize;
    let cuts: Vec<String> = chunker
        .chunks(&data)
        .iter()
        .map(|c| {
            end += c.len();
            end.to_string()
        })
        .collect();
    put("chunk", "cut_points", cuts.join(","));

    let [slot_d, slot_e, mac_d, mac_e] = secsec_client::pair::__kat(
        &[0x0c; 12],
        &[b"d-pubkey", b"d-xwing"],
        &[&[0x11; 32], &[0x22; 32]],
    );
    put("pair", "slot_d", hx(&slot_d));
    put("pair", "slot_e", hx(&slot_e));
    put("pair", "mac_d", hx(&mac_d));
    put("pair", "mac_e", hx(&mac_e));

    v
}

/// Names the file documents as inputs rather than computed outputs.
const INPUT_NAMES: &[&str] = &[
    "kdf/master_key",
    "kdf/generation",
    "kdf/obj_type",
    "kdf/obj_key.id",
    "kdf/roster_entry.seq",
    "kdf/roster_keyhist.g",
    "kdf/salt",
    "aead/key",
    "aead/ad",
    "aead/plaintext",
    "object/gen",
    "object/obj_type",
    "object/path_salt",
    "object/plaintext",
    "head/ref_name",
    "head/head_nonce",
    "roster/roster_entry.plaintext",
    "roster/roster_entry.v2.salt",
    "roster/roster_keyhist.roster_key_g",
    "chunk/cdc_seed",
    "chunk/data",
    "pair/code",
    "pair/mac_d.parts",
    "pair/mac_e.parts",
];

/// One parsed vectors file: values by `section/name`, and each section's `# asserts: <crate> <test path>` claim.
struct VectorsFile {
    values: BTreeMap<String, String>,
    asserts: BTreeMap<String, (String, String)>,
}

/// Parse `[section]` headers and `name = value` lines (trailing `# comments` stripped); a repeated name is an error.
fn parse_file(text: &str) -> Result<VectorsFile, String> {
    let mut values = BTreeMap::new();
    let mut asserts = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let (name, tail) = rest
                .split_once(']')
                .ok_or_else(|| format!("unterminated section header: {line}"))?;
            section = name.trim().to_string();
            let claim = tail
                .split_once("asserts:")
                .map(|(_, c)| c.split_whitespace());
            if let Some(mut words) = claim {
                if let (Some(krate), Some(test)) = (words.next(), words.next()) {
                    asserts.insert(section.clone(), (krate.to_string(), test.to_string()));
                }
            }
            continue;
        }
        // The assignment `=` is space-preceded; an `=` inside a name such as `[g=1]` is not.
        let Some((name, rest)) = line.split_once(" =") else {
            continue;
        };
        let key = format!("{section}/{}", name.trim());
        let value = rest.split('#').next().unwrap_or("").trim().to_string();
        if values.insert(key.clone(), value).is_some() {
            return Err(format!("{key} appears twice"));
        }
    }
    Ok(VectorsFile { values, asserts })
}

/// The committed vectors file, located from this crate so any working directory works.
fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/secsec-kat-v1.txt")
}

/// Every `.rs` file under `dir`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for ent in std::fs::read_dir(dir)? {
        let path = ent?.path();
        if path.is_dir() {
            rust_sources(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Sections whose `asserts:` names a test that does not exist in that crate.
fn missing_asserting_tests(file: &VectorsFile) -> Result<Vec<String>, String> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../crates");
    let mut missing = Vec::new();
    for (section, (krate, test)) in &file.asserts {
        let mut sources = Vec::new();
        rust_sources(&crates.join(krate).join("src"), &mut sources)
            .map_err(|e| format!("[{section}] asserts crate {krate}: {e}"))?;
        let name = test.rsplit("::").next().unwrap_or(test);
        let needle = format!("fn {name}(");
        let found = sources
            .iter()
            .any(|p| std::fs::read_to_string(p).is_ok_and(|s| s.contains(&needle)));
        if !found {
            missing.push(format!("[{section}] {krate} {test}"));
        }
    }
    Ok(missing)
}

/// Every discrepancy between live code and the committed file, one message each.
fn check(computed: &BTreeMap<String, String>, file: &VectorsFile) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();
    for (name, val) in computed {
        match file.values.get(name) {
            Some(f) if f == val => {}
            Some(f) => problems.push(format!("{name} differs\n    file: {f}\n    code: {val}")),
            None => problems.push(format!("{name} is computed but absent from the file")),
        }
    }
    for name in file.values.keys() {
        if !computed.contains_key(name) && !INPUT_NAMES.contains(&name.as_str()) {
            problems.push(format!("{name} is neither computed nor a documented input"));
        }
    }
    let sections: std::collections::BTreeSet<&str> = file
        .values
        .keys()
        .filter_map(|k| k.split_once('/').map(|(s, _)| s))
        .collect();
    for s in sections {
        if !file.asserts.contains_key(s) {
            problems.push(format!("[{s}] names no asserting test"));
        }
    }
    for m in missing_asserting_tests(file)? {
        problems.push(format!("{m}: no such test"));
    }
    Ok(problems)
}

/// Recompute and compare; without `check_only`, also print the computed values for a deliberate update.
pub(crate) fn run(check_only: bool) -> Result<(), String> {
    let computed = computed();
    let path = vectors_path();
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let file = parse_file(&text)?;
    if !check_only {
        println!("# computed from live code ({} vectors):", computed.len());
        for (k, v) in &computed {
            println!("{k} = {v}");
        }
    }
    let problems = check(&computed, &file)?;
    if !problems.is_empty() {
        return Err(format!(
            "{} problem(s) in {}:\n  {}",
            problems.len(),
            path.display(),
            problems.join("\n  ")
        ));
    }
    println!(
        "vectors: all {} live-computed values match {}",
        computed.len(),
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The anti-drift check as a plain test, so CI runs it without `cargo xtask`.
    #[test]
    fn committed_vectors_match_live_code() {
        let text = std::fs::read_to_string(vectors_path()).expect("read vectors file");
        let file = parse_file(&text).expect("parse vectors file");
        let problems = check(&computed(), &file).expect("check vectors");
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }

    #[test]
    fn parse_rejects_duplicates_and_keeps_sections_apart() {
        let ok = parse_file("[a] # asserts: x t\nk = 1\n[b] # asserts: x t\nk = 2\n").unwrap();
        assert_eq!(ok.values.get("a/k").map(String::as_str), Some("1"));
        assert_eq!(ok.values.get("b/k").map(String::as_str), Some("2"));
        assert!(parse_file("[a]\nk = 1\nk = 2\n").is_err());
    }
}
