//! The key-derivation hierarchy (`secsec-Design.md` §5, §9.5); every secret output is [`Zeroizing`].

#![forbid(unsafe_code)]

use zeroize::{Zeroize, Zeroizing};

/// A 256-bit secret key, zeroized on drop.
pub type SecretKey = Zeroizing<[u8; 32]>;

// Domain-separation context labels (§9.5).
const L_ENC: &str = "secsec-enc-key-v1";
const L_ID: &str = "secsec-id-key-v1";
const L_CDC: &str = "secsec-cdc-seed-v1";
const L_HEAD: &str = "secsec-head-enc-v1";
const L_ROSTER: &str = "secsec-roster-enc-v1";
const L_REFNAME: &str = "secsec-ref-name-v1";
const L_ROSTER_ENTRY: &str = "secsec-roster-entry-v1";
const L_ROSTER_ENTRY_V2: &str = "secsec-roster-entry-v2";
const L_ROSTER_KEYHIST: &str = "secsec-roster-keyhist-v1";
const L_KEYHIST: &str = "secsec-keyhist-enc-v1";
const L_OBJ: &str = "secsec-obj-key-v1";
const MK_COMMIT_MSG_LABEL: &[u8] = b"secsec-mk-commit-v1";

/// Per-seal roster-entry salt length (§9.5 v2 entries).
pub const ROSTER_ENTRY_SALT_LEN: usize = 32;

/// `BLAKE3::derive_key(label, part_0 ‖ part_1 ‖ …)`, streamed into a hasher that is wiped afterwards.
fn derive(label: &'static str, parts: &[&[u8]]) -> SecretKey {
    let mut h = blake3::Hasher::new_derive_key(label);
    for p in parts {
        h.update(p);
    }
    let out = Zeroizing::new(*h.finalize().as_bytes());
    h.zeroize();
    out
}

/// The repository master key at generation `g` (§5); RAM-only, zeroized on drop.
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

    /// The raw key bytes, only for keyslot and key-history wrapping (§8.2, §8.3).
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.key
    }

    /// `enc_key[g][t]`, from which per-object keys derive (§9.4).
    #[must_use]
    pub fn enc_key(&self, obj_type: u8) -> SecretKey {
        derive(
            L_ENC,
            &[&self.key[..], &self.generation.to_le_bytes(), &[obj_type]],
        )
    }

    /// `id_key[g][t]`, the content-addressing key (§9.2).
    #[must_use]
    pub fn id_key(&self, obj_type: u8) -> SecretKey {
        derive(
            L_ID,
            &[&self.key[..], &self.generation.to_le_bytes(), &[obj_type]],
        )
    }

    /// `cdc_seed[g]`, the keyed-FastCDC gear seed (§9.7).
    #[must_use]
    pub fn cdc_seed(&self) -> SecretKey {
        derive(L_CDC, &[&self.key[..], &self.generation.to_le_bytes()])
    }

    /// `head_key_g`, the fresh-nonce head-blob key (§9.8).
    #[must_use]
    pub fn head_key(&self) -> SecretKey {
        derive(L_HEAD, &[&self.key[..], &self.generation.to_le_bytes()])
    }

    /// `roster_key_g`, the generation-`g` roster-encryption key (§8, §9.5).
    #[must_use]
    pub fn roster_key(&self) -> SecretKey {
        derive(L_ROSTER, &[&self.key[..]])
    }

    /// `ref_name_key`, the keyed hash hiding ref names in storage paths (§13).
    #[must_use]
    pub fn ref_name_key(&self) -> SecretKey {
        derive(L_REFNAME, &[&self.key[..]])
    }

    /// `mk_commit_g`, the generation commitment and the one `keyed_hash` in the hierarchy (§5, §9.5).
    #[must_use]
    pub fn mk_commit(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(MK_COMMIT_MSG_LABEL);
        h.update(&self.generation.to_le_bytes());
        let out = *h.finalize().as_bytes();
        h.zeroize();
        out
    }
}

/// Generation → [`MasterKey`] resolver, the read-side key ring for §8.2 cross-rotation reads.
pub trait MasterKeys {
    /// The master key for generation `g`, or `None` if this resolver does not hold it.
    fn for_gen(&self, g: u32) -> Option<&MasterKey>;
    /// The highest generation's key, which new objects are sealed under.
    fn current(&self) -> &MasterKey;

    /// The rotation-stable ref-name key, derived from generation 1 when held, else the current key (§9.5, §13).
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
        // Ascending iteration: the last value is the highest generation; a ring is never empty.
        self.values()
            .next_back()
            .expect("master-key ring is never empty")
    }
}

/// `k_obj = derive_key("secsec-obj-key-v1", enc_key ‖ id)`, unique per content address (§9.4).
#[must_use]
pub fn obj_key(enc_key: &[u8; 32], id: &[u8; 32]) -> SecretKey {
    derive(L_OBJ, &[enc_key, id])
}

/// Legacy v1 roster-entry key `k_roster_entry[g][seq]` (§9.5); read-only, v1 entries are never written.
#[must_use]
pub fn roster_entry_key(roster_key_g: &[u8; 32], seq: u64) -> SecretKey {
    derive(L_ROSTER_ENTRY, &[roster_key_g, &seq.to_le_bytes()])
}

/// v2 roster-entry key `derive_key("secsec-roster-entry-v2", roster_key_g ‖ le64(seq) ‖ salt)` (§9.5).
#[must_use]
pub fn roster_entry_key_v2(
    roster_key_g: &[u8; 32],
    seq: u64,
    salt: &[u8; ROSTER_ENTRY_SALT_LEN],
) -> SecretKey {
    derive(L_ROSTER_ENTRY_V2, &[roster_key_g, &seq.to_le_bytes(), salt])
}

/// `k_rkh_g`, the roster-key-history wrap key from `roster_key_{g+1}` (§8.2).
#[must_use]
pub fn roster_keyhist_key(roster_key_next: &[u8; 32], g: u32) -> SecretKey {
    derive(L_ROSTER_KEYHIST, &[roster_key_next, &g.to_le_bytes()])
}

/// `k_keyhist_g`, the data-key-history wrap key from `master_key_{g+1}` (§8.2).
#[must_use]
pub fn data_keyhist_key(master_key_next: &[u8; 32], g: u32) -> SecretKey {
    derive(L_KEYHIST, &[master_key_next, &g.to_le_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const MK: [u8; 32] = [0x11; 32];

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn deterministic() {
        let mk = MasterKey::new(1, MK);
        assert_eq!(&mk.enc_key(0)[..], &mk.enc_key(0)[..]);
        assert_eq!(mk.mk_commit(), mk.mk_commit());
    }

    /// The streamed derivation equals the one-shot `blake3::derive_key` over the concatenated IKM.
    #[test]
    fn streamed_derivation_matches_one_shot_formula() {
        let mk = MasterKey::new(7, MK);
        let cat = |parts: &[&[u8]]| parts.concat();
        let g = 7u32.to_le_bytes();
        assert_eq!(
            *mk.enc_key(3),
            blake3::derive_key(L_ENC, &cat(&[&MK, &g, &[3]]))
        );
        assert_eq!(
            *mk.id_key(3),
            blake3::derive_key(L_ID, &cat(&[&MK, &g, &[3]]))
        );
        assert_eq!(*mk.cdc_seed(), blake3::derive_key(L_CDC, &cat(&[&MK, &g])));
        assert_eq!(*mk.head_key(), blake3::derive_key(L_HEAD, &cat(&[&MK, &g])));
        assert_eq!(*mk.roster_key(), blake3::derive_key(L_ROSTER, &MK));
        assert_eq!(*mk.ref_name_key(), blake3::derive_key(L_REFNAME, &MK));
        let seq = 9u64.to_le_bytes();
        assert_eq!(
            *roster_entry_key(&MK, 9),
            blake3::derive_key(L_ROSTER_ENTRY, &cat(&[&MK, &seq]))
        );
        assert_eq!(
            *roster_entry_key_v2(&MK, 9, &[0x5a; 32]),
            blake3::derive_key(L_ROSTER_ENTRY_V2, &cat(&[&MK, &seq, &[0x5a; 32]]))
        );
        let mut keyed = blake3::Hasher::new_keyed(&MK);
        keyed.update(MK_COMMIT_MSG_LABEL);
        keyed.update(&g);
        assert_eq!(mk.mk_commit(), *keyed.finalize().as_bytes());
    }

    /// Every derivation family/parameterization yields a distinct key (§9.5 domain separation).
    #[test]
    fn domain_separation_all_distinct() {
        let g1 = MasterKey::new(1, MK);
        let g2 = MasterKey::new(2, [0x22; 32]);
        let rk1 = g1.roster_key();
        let rk2 = g2.roster_key();

        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut push = |k: [u8; 32]| assert!(seen.insert(k), "derivation collision: {}", hx(&k));

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
        push(*g1.ref_name_key());
        push(g1.mk_commit());
        push(g2.mk_commit());
        push(*obj_key(&rk1, &[0xAA; 32]));
        push(*obj_key(&rk1, &[0xBB; 32]));
        push(*obj_key(&rk2, &[0xAA; 32]));
        push(*roster_entry_key(&rk1, 0));
        push(*roster_entry_key(&rk1, 1));
        push(*roster_entry_key_v2(&rk1, 1, &[0; 32]));
        push(*roster_entry_key_v2(&rk1, 1, &[1; 32]));
        push(*roster_keyhist_key(&rk2, 1));
        push(*roster_keyhist_key(&rk2, 2));
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

    /// A derived key drives `secsec-aead`, and per-object keys are unique per id.
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
        let (tag, ct) = secsec_aead::seal(secsec_aead::UniqueKey::new(&k_a), ad, b"object bytes");
        assert_eq!(
            secsec_aead::open(&k_a, ad, &tag, &ct).unwrap(),
            b"object bytes"
        );
        assert_eq!(
            secsec_aead::open(&k_b, ad, &tag, &ct),
            Err(secsec_aead::AeadError)
        );
    }

    /// Frozen §9.5 KATs for `master_key = [0x11; 32]`, mirrored in `vectors/secsec-kat-v1.txt [kdf]`.
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
            hx(&roster_entry_key_v2(&rk, 1, &[0x5a; 32])[..]),
            "8bb3d6118b8427d58c2424cd8e16fb2d746f74a7618582b47c631b4a72259634"
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
