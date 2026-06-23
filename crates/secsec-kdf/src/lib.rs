//! `secsec-kdf` — the key-derivation hierarchy (`secsec-Design.md` §5, §9.5).
//!
//! Every subkey is `BLAKE3::derive_key(label, IKM)` with a distinct hardcoded label and the secret
//! in the IKM role; `mk_commit_g` is the sole `keyed_hash` exception (§9.5 note). All secret
//! outputs are [`Zeroizing`]; the master key is RAM-only (§18).

#![forbid(unsafe_code)]

use secsec_canon::Writer;
use zeroize::Zeroizing;

/// A 256-bit secret key, zeroized on drop.
pub type SecretKey = Zeroizing<[u8; 32]>;

// Domain-separation context labels (globally unique, hardcoded — §9.5).
const L_ENC: &str = "secsec-enc-key-v1";
const L_ID: &str = "secsec-id-key-v1";
const L_CDC: &str = "secsec-cdc-seed-v1";
const L_HEAD: &str = "secsec-head-enc-v1";
const L_ROSTER: &str = "secsec-roster-enc-v1";
const L_REFNAME: &str = "secsec-ref-name-v1";
const L_ROSTER_ENTRY: &str = "secsec-roster-entry-v1";
const L_ROSTER_KEYHIST: &str = "secsec-roster-keyhist-v1";
const L_KEYHIST: &str = "secsec-keyhist-enc-v1";
const L_OBJ: &str = "secsec-obj-key-v1";
const MK_COMMIT_MSG_LABEL: &[u8] = b"secsec-mk-commit-v1";

/// `derive_key(label, IKM)` with the IKM assembled (and zeroized) via a canonical [`Writer`].
fn derive(label: &'static str, build: impl FnOnce(&mut Writer)) -> SecretKey {
    let mut w = Writer::new();
    build(&mut w);
    let ikm = Zeroizing::new(w.finish());
    Zeroizing::new(blake3::derive_key(label, &ikm))
}

/// The repository master key at a given generation `g` (§5). RAM-only; zeroized on drop.
pub struct MasterKey {
    generation: u32,
    key: SecretKey,
}

impl MasterKey {
    /// Wrap raw 32-byte key material at generation `generation`.
    #[must_use]
    pub fn new(generation: u32, key: [u8; 32]) -> Self {
        Self {
            generation,
            key: Zeroizing::new(key),
        }
    }

    /// The generation `g`.
    #[must_use]
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The raw 32-byte master-key material — only for keyslot wrapping (§8.3); everything else
    /// derives subkeys instead.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.key
    }

    /// `enc_key[g][t]` — the per-(generation, type) key from which per-object keys are derived (§9.4).
    #[must_use]
    pub fn enc_key(&self, obj_type: u8) -> SecretKey {
        derive(L_ENC, |w| {
            w.raw(&self.key[..]).u32(self.generation).u8(obj_type);
        })
    }

    /// `id_key[g][t]` — the keyed-hash key for content addressing (§9.2).
    #[must_use]
    pub fn id_key(&self, obj_type: u8) -> SecretKey {
        derive(L_ID, |w| {
            w.raw(&self.key[..]).u32(self.generation).u8(obj_type);
        })
    }

    /// `cdc_seed[g]` — the keyed-FastCDC gear seed (§9.7).
    #[must_use]
    pub fn cdc_seed(&self) -> SecretKey {
        derive(L_CDC, |w| {
            w.raw(&self.key[..]).u32(self.generation);
        })
    }

    /// `head_key_g` — the per-generation key for the mutable Head-blob AEAD (§9.8). Fresh-nonce
    /// ChaCha20-Poly1305 (`secsec_aead::seal_mut`), distinct from the content-addressed object key.
    #[must_use]
    pub fn head_key(&self) -> SecretKey {
        derive(L_HEAD, |w| {
            w.raw(&self.key[..]).u32(self.generation);
        })
    }

    /// `roster_key_g` — the generation-`g` roster-encryption key (§8, §9.5).
    #[must_use]
    pub fn roster_key(&self) -> SecretKey {
        derive(L_ROSTER, |w| {
            w.raw(&self.key[..]);
        })
    }

    /// `ref_name_key` — keyed hash that obfuscates ref names in storage paths (§13).
    #[must_use]
    pub fn ref_name_key(&self) -> SecretKey {
        derive(L_REFNAME, |w| {
            w.raw(&self.key[..]);
        })
    }

    /// `mk_commit_g` — the public, hiding, binding generation commitment (§5). The one `keyed_hash`
    /// in the hierarchy (§9.5 note); `g` is bound into the message (generation-rollback guard).
    #[must_use]
    pub fn mk_commit(&self) -> [u8; 32] {
        let mut w = Writer::new();
        w.raw(MK_COMMIT_MSG_LABEL).u32(self.generation);
        let msg = w.finish();
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&msg);
        *h.finalize().as_bytes()
    }
}

/// Generation → [`MasterKey`] resolver — the read-side key ring for §8.2 cross-rotation reads.
/// Implemented for a single [`MasterKey`] (its own generation only) and for
/// `BTreeMap<u32, MasterKey>` (the peeled key history).
pub trait MasterKeys {
    /// The master key for generation `g`, or `None` if this resolver does not hold it.
    fn for_gen(&self, g: u32) -> Option<&MasterKey>;
    /// The current (highest) generation's master key — what new objects are sealed under.
    fn current(&self) -> &MasterKey;

    /// The rotation-stable ref-name key (§9.5/§13): derived from the **genesis** generation so the
    /// ref path never moves on rotation. A single-generation resolver falls back to its own key.
    fn ref_name_key(&self) -> SecretKey {
        self.for_gen(1)
            .unwrap_or_else(|| self.current())
            .ref_name_key()
    }
}

impl MasterKeys for MasterKey {
    fn for_gen(&self, g: u32) -> Option<&MasterKey> {
        (self.generation == g).then_some(self)
    }
    fn current(&self) -> &MasterKey {
        self
    }
}

impl MasterKeys for std::collections::BTreeMap<u32, MasterKey> {
    fn for_gen(&self, g: u32) -> Option<&MasterKey> {
        self.get(&g)
    }
    fn current(&self) -> &MasterKey {
        // BTreeMap iterates in ascending key order; the last value is the highest generation. A key
        // ring is never empty (it always holds at least the current generation).
        self.values()
            .next_back()
            .expect("master-key ring is never empty")
    }
}

/// `k_obj` — the unique per-object AEAD key (§9.4): `derive_key("secsec-obj-key-v1", enc_key ‖ id)`.
///
/// Because `id` is the content address (collision-resistant over the plaintext), `k_obj` is unique
/// per object — which is exactly what makes the fixed-nonce AEAD in `secsec-aead` sound.
#[must_use]
pub fn obj_key(enc_key: &[u8; 32], id: &[u8; 32]) -> SecretKey {
    derive(L_OBJ, |w| {
        w.raw(enc_key).raw(id);
    })
}

/// `k_roster_entry[g][seq]` (§8.1, §9.5): per-sequence roster-entry key under `roster_key_g`.
#[must_use]
pub fn roster_entry_key(roster_key_g: &[u8; 32], seq: u64) -> SecretKey {
    derive(L_ROSTER_ENTRY, |w| {
        w.raw(roster_key_g).u64(seq);
    })
}

/// `k_rkh_g` (§8.2): roster-key-history forward-wrap key, derived from `roster_key_{g+1}`.
#[must_use]
pub fn roster_keyhist_key(roster_key_next: &[u8; 32], g: u32) -> SecretKey {
    derive(L_ROSTER_KEYHIST, |w| {
        w.raw(roster_key_next).u32(g);
    })
}

/// `k_keyhist_g` (§8.2): DATA-key-history forward-wrap key, derived from `master_key_{g+1}` —
/// distinct label and IKM from [`roster_keyhist_key`].
#[must_use]
pub fn data_keyhist_key(master_key_next: &[u8; 32], g: u32) -> SecretKey {
    derive(L_KEYHIST, |w| {
        w.raw(master_key_next).u32(g);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const MK: [u8; 32] = [0x11; 32];

    fn hx(b: &[u8]) -> String {
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }

    #[test]
    fn deterministic() {
        let mk = MasterKey::new(1, MK);
        assert_eq!(&mk.enc_key(0)[..], &mk.enc_key(0)[..]);
        assert_eq!(mk.mk_commit(), mk.mk_commit());
    }

    /// Every derivation family/parameterization yields a distinct key (§9.5 domain separation).
    #[test]
    fn domain_separation_all_distinct() {
        // g2 gets different key bytes, as a real Rotate mints a fresh random master key.
        let g1 = MasterKey::new(1, MK);
        let g2 = MasterKey::new(2, [0x22; 32]);
        let rk1 = g1.roster_key();
        let rk2 = g2.roster_key();

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut push = |k: [u8; 32]| assert!(seen.insert(k), "derivation collision: {}", hx(&k));

        // label separation + type separation + generation separation
        push(*g1.enc_key(0));
        push(*g1.enc_key(1));
        push(*g2.enc_key(0));
        push(*g1.id_key(0));
        push(*g1.id_key(1));
        push(*g2.id_key(0));
        push(*g1.cdc_seed());
        push(*g2.cdc_seed());
        push(*g1.head_key());
        push(*g2.head_key());
        push(*rk1);
        push(*rk2);
        push(*g1.ref_name_key()); // ref_name_key has no gen input → same across g; push once
        push(g1.mk_commit());
        push(g2.mk_commit());
        push(*obj_key(&rk1, &[0xAA; 32]));
        push(*obj_key(&rk1, &[0xBB; 32])); // different id
        push(*obj_key(&rk2, &[0xAA; 32])); // different enc_key input
        push(*roster_entry_key(&rk1, 0));
        push(*roster_entry_key(&rk1, 1));
        push(*roster_keyhist_key(&rk2, 1));
        push(*roster_keyhist_key(&rk2, 2));
        // DATA key-history: distinct from roster_keyhist (different label) and gen-separated.
        push(*data_keyhist_key(&[0x22; 32], 1));
        push(*data_keyhist_key(&[0x22; 32], 2));
    }

    #[test]
    fn mk_commit_binds_generation() {
        assert_ne!(
            MasterKey::new(1, MK).mk_commit(),
            MasterKey::new(2, MK).mk_commit(),
            "mk_commit must differ across generations (rollback guard)"
        );
    }

    /// The kdf -> aead bridge: a key derived here must seal/open under `secsec-aead`, and the
    /// per-object key must be unique per id (so the fixed nonce is sound).
    #[test]
    fn derived_obj_key_drives_aead() {
        let mk = MasterKey::new(7, MK);
        let enc = mk.enc_key(0);
        let id_a = [0x01u8; 32];
        let id_b = [0x02u8; 32];
        let k_a = obj_key(&enc, &id_a);
        let k_b = obj_key(&enc, &id_b);
        assert_ne!(
            &k_a[..],
            &k_b[..],
            "distinct ids must give distinct object keys"
        );

        let ad = b"FRAME||id_a";
        let (tag, ct) = secsec_aead::seal(&k_a, ad, b"object bytes");
        assert_eq!(
            secsec_aead::open(&k_a, ad, &tag, &ct).unwrap(),
            b"object bytes"
        );
        // the other object's key must not open it
        assert_eq!(
            secsec_aead::open(&k_b, ad, &tag, &ct),
            Err(secsec_aead::AeadError)
        );
    }

    /// Frozen §9.5 KATs for `master_key = [0x11; 32]`, mirrored in `vectors/secsec-kat-v1.txt [kdf]`
    /// (drift-checked by `cargo xtask vectors --check`).
    #[test]
    fn kat_frozen() {
        let g1 = MasterKey::new(1, MK);
        let rk = g1.roster_key();
        assert_eq!(
            hx(&g1.enc_key(0)[..]),
            "f4980c049361ccff05371f5c95680bc6563786007cfb1cf94af33feef51c7102"
        );
        assert_eq!(
            hx(&g1.id_key(0)[..]),
            "8cb578fd23622f39495fceb7bbaa8871d231d91d0fd5262be2481800ad2f4e27"
        );
        assert_eq!(
            hx(&g1.cdc_seed()[..]),
            "6e792c1fbab509b44804004092e25b29de446feb222d27dab4da456627fadb69"
        );
        assert_eq!(
            hx(&g1.head_key()[..]),
            "b3e31ff53215dd1303397a658d6b31db1ed3ab63065a5fc4742e420784cf33b8"
        );
        assert_eq!(
            hx(&rk[..]),
            "0ed99fa51a9e04918a45048b508afb58b38f14b8614d4d0d0c72e3d9a5f26fe7"
        );
        assert_eq!(
            hx(&g1.ref_name_key()[..]),
            "fb53df1905087813330741d575f364bc8a32343cafa3105f9d5e1fc337520ac3"
        );
        assert_eq!(
            hx(&g1.mk_commit()),
            "73300b1d7cdd3cd2baeffd447f1b3ffdafde8e0e2f36c7c6feb99ed1cabf96a2"
        );
        assert_eq!(
            hx(&obj_key(&rk, &[0x22; 32])[..]),
            "fe2d3fc22b54a0ca49b74df325a9f5202bf03e16b0ece7788f77236f3f18fe2b"
        );
        assert_eq!(
            hx(&roster_entry_key(&rk, 1)[..]),
            "0866a38d6c6924ac9b411189b06e3a7c15ad01c94ff4bae11f11fc6a53b640aa"
        );
        assert_eq!(
            hx(&roster_keyhist_key(&rk, 1)[..]),
            "3e5579e871ae6deb732e967391dcd05718a6c780ec82ece500235deb2b89d7d0"
        );
        assert_eq!(
            hx(&data_keyhist_key(&[0x11; 32], 1)[..]),
            "6579b7397df7eec4ab045407b8ae9abf4fd8dead31d0ddc6a702252a89ad238b"
        );
    }
}
