//! Hot provider material, on bwk's nonce cache sessions: a session is a random
//! secret, sealed in the cache, and the public nonces it derives for the signer's
//! key, computed while the signer is unlocked so a later nonce round needs no
//! mnemonic. Allocation, ordering and encrypted storage belong to the common cache.

use std::{collections::BTreeMap, path::Path};

use bitcoin::{bip32::Fingerprint, Psbt};
use bwk::{
    bwk_descriptor::wallet::{WalletDescriptor, WalletDescriptorExt},
    bwk_sign::{
        error::Error as SignerError,
        hot_signer::HotSigner,
        musig::{expression_slots, musig_status, own_slots, slot_infos, MusigRound, SlotInfo},
        nonce_cache::{SessionSecret, SECRET_LEN},
    },
    bwk_tx::bwk_psbt::musig::{musig_input_pub_nonce, set_musig_input_pub_nonce},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::datadir,
    keys::{
        musig_sessions::{
            allocate_first_request_at, binding, descriptor, AllocationState, ExpressionSlot,
            LockedCache, Nonce, PublishedNonce, SecretPayload, Session, SessionSource,
            SigningError, MAX_INPUT, MAX_SESSIONS,
        },
        record::RouteKind,
    },
};

pub fn create_hot(signer: &HotSigner, policy: &str, quantity: usize) -> Result<(), String> {
    let mut store = LockedCache::open(&datadir().join("musig-sessions"), signer.fingerprint())?;
    if !(1..=MAX_SESSIONS).contains(&quantity) {
        return Err("session quantity must be between 1 and 8".into());
    }
    for _ in 0..quantity {
        create_locked(&mut store, signer, policy, random_id()?, None)?;
    }
    Ok(())
}

fn random_id() -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    getrandom::getrandom(&mut id).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Stores a fresh session with the public nonces its secret derives for every
/// MuSig expression of the signer, at each of the `MAX_INPUT` input positions, so a
/// nonce round needs no mnemonic. They are those of the policy's first address: an
/// aggregate then derive policy has the same participant key at every address.
pub(crate) fn create_locked(
    store: &mut LockedCache,
    signer: &HotSigner,
    policy: &str,
    id: [u8; 32],
    fetched_for: Option<[u8; 32]>,
) -> Result<(), String> {
    let parsed = descriptor(policy)?;
    let template = parsed
        .single_paths()
        .map_err(|e| e.to_string())?
        .first()
        .ok_or("no descriptor path")?
        .derive_at(0)
        .map_err(|e| e.to_string())?;
    let secret = SessionSecret::random().map_err(|e| e.to_string())?;
    let mut nonces = Vec::new();
    for input in 0..MAX_INPUT {
        for info in expression_slots(input, &template).map_err(|e| e.to_string())? {
            if info.signer.0 != signer.fingerprint() {
                continue;
            }
            nonces.push(Nonce {
                input,
                expression: info.key_expression_index,
                participant: info.slot.participant,
                bytes: public_nonce(signer, &secret, &info)?.to_vec(),
            });
        }
    }
    if nonces.is_empty() {
        return Err("policy has no MuSig expression of this key".into());
    }
    let entry = Session {
        provider: RouteKind::Hot,
        id,
        order: store.reserve_order()?,
        policy: policy.to_owned(),
        nonces,
        fetched_for,
        secret: Some(SecretPayload::seal(
            Zeroizing::new(secret.as_bytes().to_vec()),
            &secret_aad(signer.fingerprint(), policy, id),
        )?),
        qr: None,
    };
    store.insert(entry)
}

/// The public nonce `secret` derives for the signer's slot `info`, the one
/// `HotSigner::sign_nonce_cache` checks.
fn public_nonce(
    signer: &HotSigner,
    secret: &SessionSecret,
    info: &SlotInfo,
) -> Result<[u8; 66], String> {
    let input = u32::try_from(info.slot.input_index).map_err(|_| "input index out of range")?;
    let expression = u32::try_from(info.key_expression_index)
        .map_err(|_| "key expression index out of range")?;
    let mut key = signer.private_key_at(&info.signer.1);
    let mut secret_key = key.secret_bytes();
    key.non_secure_erase();
    let generated = secret.nonce(
        input,
        expression,
        &secret_key,
        &info.slot.participant.serialize(),
    );
    secret_key.zeroize();
    generated
        .map(|(_, public)| public)
        .map_err(|e| e.to_string())
}

fn decode(
    secret: Option<&SecretPayload>,
    fp: Fingerprint,
    policy_text: &str,
    id: [u8; 32],
) -> Result<SessionSecret, SigningError> {
    let secret = secret.ok_or_else(|| lost("MuSig session secret is missing"))?;
    let bytes = secret
        .open(&secret_aad(fp, policy_text, id))
        .map_err(|_| lost("MuSig session secret authentication failed"))?;
    let bytes: [u8; SECRET_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| lost("MuSig session secret is invalid"))?;
    Ok(SessionSecret::from_bytes(bytes))
}

fn lost(message: &str) -> SigningError {
    SigningError::SessionLost(message.to_owned())
}

fn secret_aad(fp: Fingerprint, policy: &str, id: [u8; 32]) -> Vec<u8> {
    let mut aad = b"silent-hot-nonce-cache-session-v1\0".to_vec();
    aad.extend_from_slice(fp.as_bytes());
    aad.extend_from_slice(&id);
    aad.extend_from_slice(policy.as_bytes());
    aad
}

impl From<SignerError> for SigningError {
    fn from(error: SignerError) -> Self {
        match error {
            SignerError::MusigSession => Self::SessionLost(error.to_string()),
            error => Self::Invalid(error.to_string()),
        }
    }
}

/// The nonces `session` publishes for the slots the transaction asks this key for:
/// the stored ones, or, with `signer` unlocked, the ones its secret derives, which
/// also covers a participant key that changes with the address. None when the
/// stored nonces do not cover the slots and no signer is unlocked.
fn session_nonces(
    session: &Session,
    real: &Psbt,
    policy: &WalletDescriptor,
    fp: Fingerprint,
    signer: Option<&HotSigner>,
) -> Result<Option<Vec<PublishedNonce>>, SigningError> {
    let infos: Vec<SlotInfo> = slot_infos(real, policy)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|info| info.signer.0 == fp)
        .collect();
    let slots: Vec<ExpressionSlot> = infos
        .iter()
        .map(|info| ExpressionSlot {
            expression: info.key_expression_index,
            slot: info.slot,
        })
        .collect();
    if let Ok(published) = session.published(&slots) {
        return Ok(Some(published));
    }
    let Some(signer) = signer else {
        return Ok(None);
    };
    let secret = decode(session.secret.as_ref(), fp, &session.policy, session.id)?;
    let mut published = Vec::with_capacity(infos.len());
    for info in &infos {
        published.push(PublishedNonce {
            input: info.slot.input_index,
            participant: info.slot.participant,
            aggregate: info.slot.aggregate,
            leaf_hash: info.slot.leaf_hash,
            bytes: public_nonce(signer, &secret, info)?.to_vec(),
        });
    }
    Ok(Some(published))
}

fn insert_nonces(real: &mut Psbt, published: &[PublishedNonce]) -> Result<(), String> {
    for entry in published {
        let input = real
            .inputs
            .get_mut(entry.input)
            .ok_or("MuSig allocation names a missing input")?;
        set_musig_input_pub_nonce(input, &entry.field()?);
    }
    Ok(())
}

/// Publishes this key's cached nonce alone: an explicit nonce round. Returns false
/// when a password is needed to generate an on-demand session, to derive the nonces
/// of an address-derived participant key, or to sign.
pub fn publish_hot(fp: Fingerprint, policy: &str, real: &mut Psbt) -> Result<bool, SigningError> {
    publish_at(&datadir().join("musig-sessions"), fp, policy, real, None)
}

/// Crafts this key's first signature request without its mnemonic: its cached
/// session and every other pending signer's are taken (`first_request_at`). False
/// when a password is needed to generate an on-demand session or to sign.
pub fn first_request_hot(
    fp: Fingerprint,
    policy: &str,
    real: &mut Psbt,
    routes: &BTreeMap<Fingerprint, RouteKind>,
) -> Result<bool, SigningError> {
    first_request_at(
        &datadir().join("musig-sessions"),
        fp,
        policy,
        real,
        routes,
        None,
    )
}

/// In the nonce round, takes this key's session (from the cache, or generated from
/// `signer` when the cache is empty), then every other pending signer's
/// (`allocate_first_request`), so the request carries the complete nonce set. False
/// when there is nothing to take: past the nonce round, or no cached session and no
/// `signer` to generate one.
pub(crate) fn first_request_at(
    root: &Path,
    fp: Fingerprint,
    policy: &str,
    real: &mut Psbt,
    routes: &BTreeMap<Fingerprint, RouteKind>,
    signer: Option<&HotSigner>,
) -> Result<bool, SigningError> {
    if !publish_at(root, fp, policy, real, signer)? {
        return Ok(false);
    }
    allocate_first_request_at(root, policy, real, routes)?;
    Ok(true)
}

pub(crate) fn publish_at(
    root: &Path,
    fp: Fingerprint,
    policy: &str,
    real: &mut Psbt,
    signer: Option<&HotSigner>,
) -> Result<bool, SigningError> {
    let parsed = descriptor(policy)?;
    let slots = own_slots(real, &parsed, fp).map_err(|e| e.to_string())?;
    if slots.is_empty() {
        return Ok(false);
    }
    if musig_status(real, &parsed)
        .map_err(|e| e.to_string())?
        .round
        != MusigRound::Nonces
    {
        return Ok(false);
    }
    let binding = binding(real, &parsed, fp)?;
    let mut store = LockedCache::open(root, fp)?;
    if let Some(allocation) = store.active(binding, policy, RouteKind::Hot)? {
        if !allocation.covers_slots(&slots) || !allocation.compatible_nonces(real, false)? {
            return Err(lost("MuSig nonces do not match their allocation"));
        }
        insert_nonces(real, &allocation.slots)?;
        return Ok(true);
    }
    let mut index = store.available(policy, RouteKind::Hot);
    if index.is_none() {
        let Some(signer) = signer else {
            return Ok(false);
        };
        create_locked(&mut store, signer, policy, random_id()?, Some(binding))?;
        index = store.available(policy, RouteKind::Hot);
    }
    let index = index.ok_or("generated MuSig session is missing")?;
    let mut next = store.state.clone();
    let session = next.available.remove(index);
    let Some(published) = session_nonces(&session, real, &parsed, fp, signer)? else {
        return Ok(false);
    };
    for entry in &published {
        if musig_input_pub_nonce(
            &real.inputs[entry.input],
            entry.participant,
            entry.aggregate,
            entry.leaf_hash,
        )
        .map_err(|e| e.to_string())?
        .is_some()
        {
            return Err(lost(
                "the transaction already carries another nonce of this key",
            ));
        }
    }
    let mut published_psbt = real.clone();
    insert_nonces(&mut published_psbt, &published)?;
    store.allocate_session(next, session, binding, policy, published)?;
    *real = published_psbt;
    Ok(true)
}

/// The caller must open and validate the mnemonic before entering this operation.
/// In the nonce round this is the first signature request: it takes every pending
/// signer's session first (`first_request_at`), `routes` naming each pending signer's
/// plan route. With no routes it is an explicit nonce round (a coordinator's MuSig
/// nonce stage) and only publishes this key's nonce.
pub fn sign_hot_session(
    signer: &HotSigner,
    policy: &str,
    real: &mut Psbt,
    routes: &BTreeMap<Fingerprint, RouteKind>,
) -> Result<(), SigningError> {
    sign_at(
        &datadir().join("musig-sessions"),
        signer,
        policy,
        real,
        routes,
    )
}

fn sign_at(
    root: &Path,
    signer: &HotSigner,
    policy: &str,
    real: &mut Psbt,
    routes: &BTreeMap<Fingerprint, RouteKind>,
) -> Result<(), SigningError> {
    let fp = signer.fingerprint();
    let parsed = descriptor(policy)?;
    if routes.is_empty() {
        if publish_at(root, fp, policy, real, Some(signer))? {
            return Ok(());
        }
    } else {
        first_request_at(root, fp, policy, real, routes, Some(signer))?;
    }
    let binding = binding(real, &parsed, fp)?;
    let mut store = LockedCache::open(root, fp)?;
    let allocation = store
        .active(binding, policy, RouteKind::Hot)?
        .ok_or_else(|| lost("MuSig session allocation is missing"))?;
    let slots = own_slots(real, &parsed, fp).map_err(|e| e.to_string())?;
    if !allocation.covers_slots(&slots) || !allocation.compatible_nonces(real, true)? {
        return Err(lost("MuSig nonces do not match their allocation"));
    }
    let secret = decode(allocation.secret.as_ref(), fp, policy, allocation.id)?;
    // No signature operation can run until the whole secret has been durably burned.
    store.retire_for(binding, AllocationState::Consumed, RouteKind::Hot)?;
    signer
        .sign_nonce_cache(real, &parsed, &secret)
        .map_err(SigningError::from)?;
    if allocation.source == SessionSource::Cached {
        let refill = random_id().and_then(|id| create_locked(&mut store, signer, policy, id, None));
        if let Err(error) = refill {
            log::error!("MuSig session refill failed: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path, str::FromStr};

    use bitcoin::{
        absolute::LockTime, bip32::DerivationPath, transaction::Version, Amount, Network, OutPoint,
        Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bwk::{
        bwk_descriptor::{updater::update_input, wallet::WalletDescriptorExt},
        bwk_sign::{hot_signer::HotSigner, musig::musig_status},
        bwk_tx::bwk_psbt::{
            musig::{musig_input_partial_sigs, musig_input_pub_nonces, set_musig_input_pub_nonce},
            PsbtV2,
        },
    };
    use temp_dir::TempDir;

    use crate::{
        keys::{
            musig_sessions::{
                descriptor,
                hot_provider::{create_locked, first_request_at, publish_at, secret_aad, sign_at},
                restart_at, AllocationState, LockedCache, SessionSource, SigningError,
            },
            record::RouteKind,
        },
        state_crypt,
    };

    const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MNEMONIC_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    fn signers() -> (HotSigner, HotSigner) {
        (
            HotSigner::new_from_mnemonics(Network::Regtest, MNEMONIC_A).expect("signer A"),
            HotSigner::new_from_mnemonics(Network::Regtest, MNEMONIC_B).expect("signer B"),
        )
    }

    /// Aggregate then derive, as Reckless's accounts: the participant keys are the
    /// same at every address.
    fn policy(a: &HotSigner, b: &HotSigner, account: u32) -> String {
        let path = DerivationPath::from_str(&format!("m/87'/1'/{account}'")).expect("account path");
        format!(
            "tr(musig([{}/87h/1h/{}h]{},[{}/87h/1h/{}h]{})/<0;1>/*)",
            a.fingerprint(),
            account,
            a.xpub(&path).xkey,
            b.fingerprint(),
            account,
            b.xpub(&path).xkey
        )
    }

    fn transaction(policy: &str, branch: usize, index: u32) -> Psbt {
        let parsed = descriptor(policy).expect("policy");
        let definite = parsed.single_paths().expect("paths")[branch]
            .derive_at(index)
            .expect("derive address");
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: definite.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("PSBT");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: definite.script_pubkey(),
        });
        update_input(&mut psbt, 0, &definite).expect("input metadata");
        psbt
    }

    fn create(root: &Path, signer: &HotSigner, policy: &str, id: u8) {
        let mut store = LockedCache::open(root, signer.fingerprint()).expect("open cache");
        create_locked(&mut store, signer, policy, [id; 32], None).expect("create session");
    }

    fn count(root: &Path, signer: &HotSigner, policy: &str) -> usize {
        LockedCache::open(root, signer.fingerprint())
            .expect("reopen cache")
            .state
            .available
            .iter()
            .filter(|entry| entry.provider == RouteKind::Hot && entry.policy == policy)
            .count()
    }

    fn peer_nonces(b: &HotSigner, policy: &str, psbt: &mut Psbt) {
        let parsed = descriptor(policy).expect("policy");
        // The peer's first MuSig2 round adds its public nonces only.
        b.inner_sign(psbt, &parsed).expect("peer nonces");
    }

    fn lifecycle(cached: bool) {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        if cached {
            for id in 1..=4 {
                create(tmp.path(), &a, &policy, id);
            }
        }
        assert_eq!(
            count(tmp.path(), &a, &policy),
            if cached { 4 } else { 0 },
            "initial queue"
        );
        let mut tx = transaction(&policy, 1, 42);
        if cached {
            assert!(
                publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
                    .expect("passwordless publication")
            );
        } else {
            assert!(
                !publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
                    .expect("password needed")
            );
            assert!(
                publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, Some(&a))
                    .expect("on-demand publication while unlocked")
            );
        }
        assert_eq!(
            count(tmp.path(), &a, &policy),
            if cached { 3 } else { 0 },
            "allocated whole session"
        );
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("reopen between rounds");
        let allocation = &store.state.allocated[0];
        assert_eq!(
            allocation.id,
            if cached { [1; 32] } else { allocation.id },
            "FIFO ignores ID order"
        );
        assert_eq!(
            allocation.source,
            if cached {
                SessionSource::Cached
            } else {
                SessionSource::FetchedForSigning
            }
        );
        let secret_json = serde_json::to_string(allocation.secret.as_ref().expect("active secret"))
            .expect("secret encoding");
        assert!(
            state_crypt::is_sealed(&fs::read(&store.path).expect("sealed disk state")),
            "secrets are encrypted"
        );
        drop(store);
        peer_nonces(&b, &policy, &mut tx);
        assert!(musig_status(&tx, &descriptor(&policy).expect("policy"))
            .expect("status")
            .cosigners
            .iter()
            .all(|entry| entry.nonces == entry.expected));
        sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new())
            .expect("round two after reopening");
        assert_eq!(
            musig_input_partial_sigs(&tx.inputs[0])
                .expect("partial signatures")
                .len(),
            1,
            "one owned signature"
        );
        assert_eq!(
            count(tmp.path(), &a, &policy),
            if cached { 4 } else { 0 },
            "only cached origin refills"
        );
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("reopen consumed state");
        assert_eq!(store.state.allocated[0].state, AllocationState::Consumed);
        assert!(
            store.state.allocated[0].secret.is_none(),
            "consumed root absent from disk"
        );
        let json = state_crypt::read_state(&store.path)
            .expect("decrypt")
            .expect("persisted state");
        assert!(
            !json.contains(&secret_json),
            "old secret not retained by a refill"
        );
        drop(store);
        assert!(
            matches!(
                sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()),
                Err(SigningError::SessionLost(_))
            ),
            "consumed session cannot be reused"
        );
    }

    #[test]
    fn cached_four_to_three_to_four_with_real_address_derivation_and_reopen() {
        lifecycle(true);
    }

    #[test]
    fn on_demand_zero_to_zero_to_zero_with_reopen() {
        lifecycle(false);
    }

    fn both_hot(a: &HotSigner, b: &HotSigner) -> BTreeMap<bitcoin::bip32::Fingerprint, RouteKind> {
        BTreeMap::from([
            (a.fingerprint(), RouteKind::Hot),
            (b.fingerprint(), RouteKind::Hot),
        ])
    }

    fn nonces_complete(policy: &str, tx: &Psbt) -> bool {
        musig_status(tx, &descriptor(policy).expect("policy"))
            .expect("status")
            .cosigners
            .iter()
            .all(|entry| entry.nonces == entry.expected)
    }

    fn peer_allocation(root: &Path, b: &HotSigner) -> AllocationState {
        LockedCache::open(root, b.fingerprint())
            .expect("peer cache")
            .state
            .allocated[0]
            .state
    }

    #[test]
    fn a_passwordless_first_request_takes_every_required_signers_session() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        create(tmp.path(), &b, &policy, 2);
        let routes = both_hot(&a, &b);
        let mut tx = transaction(&policy, 0, 3);
        assert!(
            first_request_at(tmp.path(), a.fingerprint(), &policy, &mut tx, &routes, None)
                .expect("first request crafted without a password"),
            "a cached session crafts the request"
        );
        assert!(
            nonces_complete(&policy, &tx),
            "the request carries every required signer's nonces"
        );
        assert_eq!(count(tmp.path(), &a, &policy), 0, "own session taken");
        assert_eq!(count(tmp.path(), &b, &policy), 0, "peer session taken");
        assert_eq!(
            peer_allocation(tmp.path(), &b),
            AllocationState::Active,
            "the peer's session is bound to this attempt"
        );
        sign_at(tmp.path(), &a, &policy, &mut tx, &routes).expect("password signs the request");
        assert_eq!(
            musig_input_partial_sigs(&tx.inputs[0])
                .expect("partial signatures")
                .len(),
            1,
            "the first request signs"
        );
    }

    #[test]
    fn an_unlocked_first_request_takes_every_required_signers_session_and_signs() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &b, &policy, 2);
        let mut tx = transaction(&policy, 1, 4);
        sign_at(tmp.path(), &a, &policy, &mut tx, &both_hot(&a, &b))
            .expect("first signature request");
        assert!(
            nonces_complete(&policy, &tx),
            "the request carries every required signer's nonces"
        );
        assert_eq!(count(tmp.path(), &b, &policy), 0, "peer session taken");
        assert_eq!(
            peer_allocation(tmp.path(), &b),
            AllocationState::Active,
            "the peer's session is bound to this attempt"
        );
        assert_eq!(
            musig_input_partial_sigs(&tx.inputs[0])
                .expect("partial signatures")
                .len(),
            1,
            "the first request signs, with no second request"
        );
    }

    #[test]
    fn same_id_is_fresh_and_invalidates_allocations_in_every_state() {
        for state in [
            AllocationState::Active,
            AllocationState::Consumed,
            AllocationState::Invalid,
        ] {
            let tmp = TempDir::new().expect("temp directory");
            let (a, b) = signers();
            let policy = policy(&a, &b, 0);
            create(tmp.path(), &a, &policy, 8);
            create(tmp.path(), &a, &policy, 1);
            let mut tx = transaction(&policy, 0, 0);
            publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
                .expect("allocate first");
            let first = musig_input_pub_nonces(&tx.inputs[0]).expect("first nonces");
            {
                let mut store = LockedCache::open(tmp.path(), a.fingerprint()).expect("open");
                assert_eq!(
                    store.state.allocated[0].id, [8; 32],
                    "FIFO uses order, not ID"
                );
                let binding = store.state.allocated[0].binding;
                store
                    .retire_for(binding, state, RouteKind::Hot)
                    .expect("set allocation state");
                create_locked(&mut store, &a, &policy, [8; 32], None).expect("replace same ID");
                assert_eq!(
                    store.state.allocated[0].state,
                    AllocationState::Invalid,
                    "old allocation invalidated in every state"
                );
                assert!(
                    store.state.allocated[0].secret.is_none(),
                    "old secret erased"
                );
                assert_eq!(store.state.available.len(), 2, "other ID retained");
                let replacement = store
                    .state
                    .available
                    .iter()
                    .find(|entry| entry.id == [8; 32])
                    .expect("replacement");
                assert_ne!(
                    replacement.nonces[0].bytes, first[0].nonce,
                    "replacement root is fresh"
                );
            }
            peer_nonces(&b, &policy, &mut tx);
            assert!(
                matches!(
                    sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()),
                    Err(SigningError::SessionLost(_))
                ),
                "old allocation cannot sign"
            );
        }
    }

    #[test]
    fn providers_and_policies_remain_independent_after_reopen() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let first = policy(&a, &b, 0);
        let second = policy(&a, &b, 1);
        create(tmp.path(), &a, &first, 1);
        create(tmp.path(), &a, &second, 1);
        {
            let mut store = LockedCache::open(tmp.path(), a.fingerprint()).expect("open");
            let mut hardware = store.state.available[0].clone();
            hardware.provider = RouteKind::Usb;
            hardware.secret = None;
            store
                .insert(hardware)
                .expect("hardware entry shares fingerprint and ID");
        }
        create(tmp.path(), &a, &first, 1);
        let mut tx = transaction(&first, 1, 5);
        publish_at(tmp.path(), a.fingerprint(), &first, &mut tx, None).expect("hot allocation");
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("reopen");
        assert_eq!(
            store.state.available.len(),
            2,
            "other policy and provider retained"
        );
        assert!(store
            .state
            .available
            .iter()
            .any(|entry| entry.provider == RouteKind::Usb && entry.policy == first));
        assert!(store
            .state
            .available
            .iter()
            .any(|entry| entry.provider == RouteKind::Hot && entry.policy == second));
        assert_eq!(
            store.state.allocated[0].provider,
            RouteKind::Hot,
            "hardware material never allocated by hot route"
        );
    }

    #[test]
    fn write_failures_release_neither_nonce_nor_signature() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        let path = LockedCache::open(tmp.path(), a.fingerprint())
            .expect("open")
            .path
            .with_extension("tmp");
        fs::create_dir(&path).expect("block atomic write");
        let mut tx = transaction(&policy, 1, 12);
        let original = tx.clone();
        assert!(publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None).is_err());
        assert_eq!(
            tx, original,
            "no public nonces released when allocation cannot persist"
        );
        assert_eq!(count(tmp.path(), &a, &policy), 1, "available root retained");
        fs::remove_dir(&path).expect("allow write");
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None).expect("publish");
        peer_nonces(&b, &policy, &mut tx);
        let nonces = tx.clone();
        fs::create_dir(&path).expect("block burn");
        assert!(sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()).is_err());
        assert_eq!(tx, nonces, "signer never called before durable burn");
        assert!(
            LockedCache::open(tmp.path(), a.fingerprint())
                .expect("reopen")
                .state
                .allocated[0]
                .secret
                .is_some(),
            "failed write did not burn root"
        );
    }

    #[test]
    fn failed_signing_consumes_secret_and_never_refills() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        let mut tx = transaction(&policy, 0, 1);
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None).expect("publish");
        peer_nonces(&b, &policy, &mut tx);
        // Replace the peer nonce with an invalid point, leaving the owned nonce intact.
        let own = descriptor(&policy).expect("policy");
        let peer =
            bwk::bwk_sign::musig::own_slots(&tx, &own, b.fingerprint()).expect("peer slots")[0];
        let mut field = musig_input_pub_nonces(&tx.inputs[0])
            .expect("nonces")
            .into_iter()
            .find(|field| field.participant == peer.participant)
            .expect("peer nonce");
        field.nonce = [0; 66];
        set_musig_input_pub_nonce(&mut tx.inputs[0], &field);
        let before = tx.clone();
        assert!(
            sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()).is_err(),
            "invalid peer nonce fails signing"
        );
        assert_eq!(tx, before, "upstream signing failure leaves PSBT unchanged");
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("reopen");
        assert_eq!(store.state.allocated[0].state, AllocationState::Consumed);
        assert!(
            store.state.allocated[0].secret.is_none(),
            "failure never restores root"
        );
        assert!(
            store.state.available.is_empty(),
            "failure never refills cached origin"
        );
        drop(store);
        assert!(matches!(
            sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()),
            Err(SigningError::SessionLost(_))
        ));
    }

    #[test]
    fn refill_failure_keeps_the_successful_signature() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        let mut tx = transaction(&policy, 0, 2);
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None).expect("publish");
        peer_nonces(&b, &policy, &mut tx);
        {
            let mut store = LockedCache::open(tmp.path(), a.fingerprint()).expect("open");
            let mut next = store.state.clone();
            next.fetch_order = u64::MAX;
            store.save(next).expect("exhaust refill order");
        }
        sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new())
            .expect("successful signature survives refill failure");
        assert_eq!(
            musig_input_partial_sigs(&tx.inputs[0])
                .expect("partial signature")
                .len(),
            1
        );
        assert_eq!(
            count(tmp.path(), &a, &policy),
            0,
            "replacement could not be persisted"
        );
    }

    #[test]
    fn restart_burns_hot_allocation_and_keeps_available_sessions() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        create(tmp.path(), &a, &policy, 2);
        let mut tx = transaction(&policy, 1, 12);
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None).expect("publish");
        let bytes = PsbtV2::from_bitcoin_psbt(tx.clone())
            .expect("v2")
            .serialize()
            .expect("serialize");
        let restarted =
            restart_at(tmp.path(), &policy, &bytes, &bytes, &[a.fingerprint()]).expect("restart");
        let mut restarted = PsbtV2::deserialize(&restarted)
            .expect("v2")
            .into_bitcoin_psbt()
            .expect("v0");
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("reopen");
        assert_eq!(store.state.allocated[0].state, AllocationState::Invalid);
        assert!(
            store.state.allocated[0].secret.is_none(),
            "restart durably burns allocation"
        );
        assert_eq!(store.state.available.len(), 1, "inactive queue retained");
        drop(store);
        peer_nonces(&b, &policy, &mut tx);
        assert!(matches!(
            sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new()),
            Err(SigningError::SessionLost(_))
        ));
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut restarted, None)
            .expect("new attempt uses next cached session");
        assert_eq!(count(tmp.path(), &a, &policy), 0);
    }

    #[test]
    fn prefetch_covers_eight_positions_and_every_owned_expression() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let expression = |account| {
            let text = policy(&a, &b, account);
            text.strip_prefix("tr(")
                .expect("tr")
                .strip_suffix(')')
                .expect("closing tr")
                .to_owned()
        };
        let policy = format!(
            "tr({},{{pk({}),pk({})}})",
            expression(0),
            expression(1),
            expression(2)
        );
        create(tmp.path(), &a, &policy, 1);
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("open");
        assert_eq!(
            store.state.available[0].nonces.len(),
            24,
            "eight absolute positions for all three expressions"
        );
        for input in 0..8 {
            for expression in 0..3 {
                assert!(
                    store.state.available[0]
                        .nonces
                        .iter()
                        .any(|nonce| nonce.input == input && nonce.expression == expression),
                    "input {input}, expression {expression} covered"
                );
            }
        }
        drop(store);
        let mut tx = transaction(&policy, 1, 25);
        let input = tx.inputs[0].clone();
        let txin = tx.unsigned_tx.input[0].clone();
        for index in 1..8 {
            tx.inputs.push(input.clone());
            let mut txin = txin.clone();
            txin.previous_output.vout = index;
            tx.unsigned_tx.input.push(txin);
        }
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
            .expect("publish real derivations at every position");
        for input in &tx.inputs {
            assert!(
                !musig_input_pub_nonces(input)
                    .expect("public nonces")
                    .is_empty(),
                "every covered position publishes"
            );
        }
    }

    #[test]
    fn stale_owned_nonce_with_new_binding_and_missing_peers_is_session_lost() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        create(tmp.path(), &a, &policy, 2);
        let mut tx = transaction(&policy, 0, 0);
        publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
            .expect("first nonce allocation");
        tx.unsigned_tx.output[0].value = Amount::from_sat(89_999);
        let before = tx.clone();
        assert!(
            matches!(
                publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None),
                Err(SigningError::SessionLost(_))
            ),
            "upstream stale own nonce requires a restart, even while peer nonces are missing"
        );
        assert_eq!(tx, before, "failed publication returns no new nonce");
        assert_eq!(
            count(tmp.path(), &a, &policy),
            1,
            "refused session remains unpublished"
        );
        assert!(
            matches!(
                SigningError::from(bwk::bwk_sign::error::Error::SigningInfo),
                SigningError::Invalid(_)
            ),
            "ordinary upstream errors retain their kind"
        );
    }

    #[test]
    fn an_address_derived_participant_needs_the_unlocked_signer() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let path = DerivationPath::from_str("m/87'/1'/0'").expect("account path");
        let policy = format!(
            "tr(musig([{}/87h/1h/0h]{}/<0;1>/*,[{}/87h/1h/0h]{}/<0;1>/*))",
            a.fingerprint(),
            a.xpub(&path).xkey,
            b.fingerprint(),
            b.xpub(&path).xkey
        );
        create(tmp.path(), &a, &policy, 1);
        let mut tx = transaction(&policy, 0, 3);
        let original = tx.clone();
        assert!(
            !publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, None)
                .expect("passwordless publication"),
            "the stored nonces are those of the first address: a password is needed"
        );
        assert_eq!(tx, original, "nothing is published without the signer");
        assert_eq!(
            count(tmp.path(), &a, &policy),
            1,
            "the session stays available"
        );
        assert!(
            publish_at(tmp.path(), a.fingerprint(), &policy, &mut tx, Some(&a))
                .expect("unlocked publication"),
            "the unlocked signer derives the nonces from the session secret"
        );
        assert_eq!(
            count(tmp.path(), &a, &policy),
            0,
            "the session is allocated"
        );
        peer_nonces(&b, &policy, &mut tx);
        sign_at(tmp.path(), &a, &policy, &mut tx, &BTreeMap::new())
            .expect("the unlocked signer signs");
        assert_eq!(
            musig_input_partial_sigs(&tx.inputs[0])
                .expect("partial signatures")
                .len(),
            1,
            "the own partial signature is in"
        );
    }

    #[test]
    fn outer_decrypted_json_contains_only_inner_ciphertext_for_hot_roots() {
        let tmp = TempDir::new().expect("temp directory");
        let (a, b) = signers();
        let policy = policy(&a, &b, 0);
        create(tmp.path(), &a, &policy, 1);
        let store = LockedCache::open(tmp.path(), a.fingerprint()).expect("open cache");
        let session = &store.state.available[0];
        let secret = session.secret.as_ref().expect("inner ciphertext");
        let aad = secret_aad(a.fingerprint(), &policy, session.id);
        let raw = secret.open(&aad).expect("open inner payload");
        assert_eq!(raw.len(), 32, "a nonce cache session secret");
        let json = state_crypt::read_state(&store.path)
            .expect("decrypt outer BIP138")
            .expect("persisted cache");
        let encoded = serde_json::to_string(raw.as_slice()).expect("secret bytes");
        assert!(
            !json.contains(&encoded),
            "outer serialization has no clear session secret"
        );
        assert!(
            secret
                .open(&secret_aad(a.fingerprint(), &policy, [2; 32]))
                .is_err(),
            "inner AEAD binds the session ID"
        );
        assert!(
            secret
                .open(&secret_aad(a.fingerprint(), "another policy", session.id))
                .is_err(),
            "inner AEAD binds the policy"
        );
    }
}
