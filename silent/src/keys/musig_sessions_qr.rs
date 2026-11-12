//! QR protocol adapter for the shared MuSig session cache, on bwk's QR MuSig host and
//! the nonce cache sessions of bwk's `bip-nonce-cache` draft: nonce preparation,
//! readiness, allocation at the first signature request, and the signing answer.
//!
//! Records are public-only by construction: a QR peer keeps its session secrets, so a
//! cache record never carries more than the public nonces the peer issued.

use std::{collections::BTreeMap, path::Path};

use bipqr::ll::{request, response::Capabilities, RequestId};
use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    psbt::raw,
    Psbt,
};
use bwk::{
    bwk_descriptor::wallet::{WalletDescriptor, WalletDescriptorExt},
    bwk_sign::{
        identity::SignerId,
        musig::{expression_slots, slot_infos, MusigSlot, SlotInfo},
        nonce_cache::SESSION_ID_LEN,
        protocol::{RequestId as OuterRequestId, Response as OuterResponse},
        qr_musig::MAX_NONCE_EXPRESSIONS,
        qr_musig_host::{
            encode_host_record, Issuance, NoncePosition, QrMusigHost, QrMusigHostRecord,
            QrMusigHostResponse,
        },
    },
    bwk_tx::bwk_psbt::{
        musig::{
            musig_input_partial_sig, musig_input_pub_nonce, set_musig_input_partial_sig,
            set_musig_input_pub_nonce, MusigPartialSig,
        },
        nonce_cache::PSBT_GLOBAL_NONCE_CACHE_SESSION,
    },
    persist::{
        backend::noop::NoopBackend,
        storage::{ram::RamStore, Store},
    },
};

use crate::{
    config::datadir,
    hwi,
    keys::{
        musig_sessions::{
            binding, descriptor, qr_first_request_at, AllocationState, Cache, LockedCache,
            PublishedNonce, QrSessionRecord, Session, SigningError, MAX_INPUT,
        },
        psbt,
        record::RouteKind,
    },
};

type HostStore = RamStore<NoopBackend, [u8; SESSION_ID_LEN], QrMusigHostRecord>;
pub(crate) type Host = QrMusigHost<HostStore>;

/// The capability bwk's host requires of a peer. A plan routes a MuSig signer to the
/// QR cache only when its device advertised it (`CAPABILITY_MUSIG_CACHE`).
pub(crate) const PEER_CAPABILITIES: Capabilities = Capabilities(Capabilities::NONCE_CACHE);

/// A durable nonce preparation: the host holding the session's record, from which
/// the GUI thread builds the request under its own request id.
pub struct QrPreparationMaterial {
    pub(crate) host: Host,
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    pub(crate) issuance: Issuance,
}

/// A durable first signature request allocation: the host holding the allocated
/// session's record, the policy entry and the transaction the request signs.
pub struct QrSigningMaterial {
    pub(crate) host: Host,
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    pub(crate) descriptor: request::Descriptor,
    pub(crate) psbt: Psbt,
}

/// A peer's answer to a nonce cache request, handed to the host that asked it.
pub struct QrMusigAnswer {
    pub(crate) host: Host,
    pub(crate) session_id: [u8; SESSION_ID_LEN],
    /// The PSBT the Signing request carried. `None` for a preparation.
    pub(crate) sent: Option<Psbt>,
    pub(crate) payload: Vec<u8>,
}

impl std::fmt::Debug for QrMusigAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QrMusigAnswer")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl QrSessionRecord {
    fn host_record(&self) -> Result<QrMusigHostRecord, String> {
        QrMusigHostRecord::decode(&self.record).map_err(|e| e.to_string())
    }

    fn new(session_id: [u8; SESSION_ID_LEN], record: &QrMusigHostRecord) -> Result<Self, String> {
        Ok(Self {
            session_id,
            record: record.encode().map_err(|e| e.to_string())?,
        })
    }

    /// Whether the peer issued a nonce for every slot of `infos`.
    fn covers(&self, infos: &[SlotInfo]) -> Result<bool, String> {
        let record = self.host_record()?;
        for info in infos {
            if !record.nonces().contains_key(&position(info)?) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Where the host stores the nonce of a slot: its participant path, key expression
/// index and input index.
fn position(info: &SlotInfo) -> Result<NoncePosition, String> {
    Ok(NoncePosition {
        path: info.signer.1.clone(),
        key_expression_index: u32::try_from(info.key_expression_index)
            .map_err(|_| "key expression index out of range")?,
        input_index: u32::try_from(info.slot.input_index)
            .map_err(|_| "input index out of range")?,
    })
}

fn signer_id(fingerprint: Fingerprint) -> SignerId {
    SignerId::new(fingerprint.to_string())
}

fn lost(message: &str) -> SigningError {
    SigningError::SessionLost(message.to_owned())
}

/// A host over `records`: the sessions of one peer.
fn host<'a>(records: impl IntoIterator<Item = &'a QrSessionRecord>) -> Result<Host, String> {
    let mut store = HostStore::empty(
        NoopBackend::new(),
        "qr-musig-host",
        |session_id| hex::encode(session_id),
        encode_host_record,
    );
    for record in records {
        store
            .insert(record.session_id, record.host_record()?)
            .map_err(|e| e.to_string())?;
    }
    Ok(QrMusigHost::from_store(store))
}

/// Every QR session the peer may still hold: the available ones and the active
/// allocations.
fn peer_records(state: &Cache) -> impl Iterator<Item = &QrSessionRecord> {
    let available = state
        .available
        .iter()
        .filter(|session| session.provider == RouteKind::Qr)
        .filter_map(|session| session.qr.as_ref());
    let allocated = state
        .allocated
        .iter()
        .filter(|allocation| {
            allocation.provider == RouteKind::Qr && allocation.state == AllocationState::Active
        })
        .filter_map(|allocation| allocation.qr.as_ref());
    available.chain(allocated)
}

/// What a preparation asks the peer for: the nonces of its participant key at every
/// key expression index the policy gives it, for `MAX_INPUT` inputs. The participant
/// key must be the same at every address (aggregate then derive), so one issuance
/// covers every transaction of the policy.
pub(crate) fn issuance(
    policy: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<Issuance, String> {
    let mut own = Vec::new();
    for single in policy.single_paths().map_err(|e| e.to_string())? {
        for index in [0, 1] {
            let definite = single.derive_at(index).map_err(|e| e.to_string())?;
            own.extend(
                expression_slots(0, &definite)
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .filter(|info| info.signer.0 == fingerprint),
            );
        }
    }
    let Some(first) = own.first() else {
        return Err("policy has no MuSig participant of this key".into());
    };
    let path: DerivationPath = first.signer.1.clone();
    if own.iter().any(|info| info.signer.1 != path) {
        return Err(
            "the QR nonce cache needs one participant key of this signer, the same at every address"
                .into(),
        );
    }
    let indexes = own.iter().map(|info| info.key_expression_index);
    let start = indexes.clone().min().unwrap_or_default();
    let end = indexes.max().unwrap_or_default();
    // bipqr leaves the bound to the signer: this is the one bwk's QR MuSig peer keeps.
    if end - start >= MAX_NONCE_EXPRESSIONS as usize {
        return Err(format!(
            "the QR nonce cache covers at most {MAX_NONCE_EXPRESSIONS} key expressions per signer"
        ));
    }
    Ok(Issuance {
        path,
        max_inputs: MAX_INPUT as u32,
        start: start as u32,
        end: end as u32,
    })
}

pub fn prepare_material(
    fingerprint: Fingerprint,
    policy_text: &str,
) -> Result<QrPreparationMaterial, String> {
    prepare_material_at(&datadir().join("musig-sessions"), fingerprint, policy_text)
}

/// Persists a fresh session record, or reuses the oldest available one of the
/// policy, and returns the host the request is built from. The record is durable
/// before any bytes leave, so a lost exchange never takes a session.
pub(crate) fn prepare_material_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
) -> Result<QrPreparationMaterial, String> {
    let issuance = issuance(&descriptor(policy_text)?, fingerprint)?;
    let mut store = LockedCache::open(root, fingerprint)?;
    let mut host = host(peer_records(&store.state))?;
    let reused = store
        .state
        .available
        .iter()
        .filter(|session| session.provider == RouteKind::Qr && session.policy == policy_text)
        .min_by_key(|session| session.order)
        .and_then(|session| session.qr.as_ref())
        .map(|qr| qr.session_id);
    let session_id = match reused {
        Some(session_id) => session_id,
        None => {
            // Only creates the record: the GUI thread asks it again under its own
            // request id.
            let (session_id, _) = host
                .issue_request(
                    signer_id(fingerprint),
                    PEER_CAPABILITIES,
                    RequestId([0, 0]),
                    fingerprint,
                    issuance.clone(),
                )
                .map_err(|e| e.to_string())?;
            host.cancel_pending();
            let record = host
                .record(&session_id)
                .map_err(|e| e.to_string())?
                .ok_or("the issued session is missing")?;
            let mut id = [0; 32];
            getrandom::getrandom(&mut id).map_err(|e| e.to_string())?;
            let order = store.reserve_order()?;
            store.insert(Session {
                provider: RouteKind::Qr,
                id,
                order,
                policy: policy_text.to_owned(),
                nonces: Vec::new(),
                fetched_for: None,
                secret: None,
                qr: Some(QrSessionRecord::new(session_id, &record)?),
            })?;
            session_id
        }
    };
    Ok(QrPreparationMaterial {
        host,
        session_id,
        issuance,
    })
}

/// Stores the nonces the host accepted on the preparation they belong to.
fn store_prepared(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    session_id: [u8; SESSION_ID_LEN],
    record: &QrMusigHostRecord,
) -> Result<(), String> {
    let mut store = LockedCache::open(root, fingerprint)?;
    let mut next = store.state.clone();
    let session = next
        .available
        .iter_mut()
        .find(|session| {
            session.provider == RouteKind::Qr
                && session.policy == policy_text
                && session
                    .qr
                    .as_ref()
                    .is_some_and(|qr| qr.session_id == session_id)
        })
        .ok_or("no preparation in flight for this session")?;
    session.qr = Some(QrSessionRecord::new(session_id, record)?);
    store.save(next)
}

/// Forgets a session the peer no longer holds: its available record goes, and an
/// active allocation of it is invalidated.
fn drop_session(
    root: &Path,
    fingerprint: Fingerprint,
    session_id: [u8; SESSION_ID_LEN],
) -> Result<(), String> {
    let holds = |qr: &Option<QrSessionRecord>| {
        qr.as_ref()
            .is_some_and(|record| record.session_id == session_id)
    };
    let mut store = LockedCache::open(root, fingerprint)?;
    let mut next = store.state.clone();
    next.available
        .retain(|session| session.provider != RouteKind::Qr || !holds(&session.qr));
    for allocation in &mut next.allocated {
        if allocation.provider == RouteKind::Qr
            && allocation.state == AllocationState::Active
            && holds(&allocation.qr)
        {
            allocation.state = AllocationState::Invalid;
        }
    }
    store.save(next)
}

pub fn accept_answer(
    fingerprint: Fingerprint,
    policy_text: &str,
    answer: QrMusigAnswer,
) -> Result<Option<Psbt>, SigningError> {
    accept_answer_at(
        &datadir().join("musig-sessions"),
        fingerprint,
        policy_text,
        answer,
    )
}

/// Hands the peer's answer to the host that asked it. A preparation answer is
/// stored on its session, a signing answer is checked against its allocation and
/// consumes it: the signed PSBT comes back. A refusal for the session forgets it.
pub(crate) fn accept_answer_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    answer: QrMusigAnswer,
) -> Result<Option<Psbt>, SigningError> {
    let QrMusigAnswer {
        mut host,
        session_id,
        sent,
        payload,
    } = answer;
    // The request went out through the QR display, not a signing manager: the outer
    // id only pairs this answer with it.
    let outer = OuterRequestId::new(0);
    host.bind_outer_request(outer).map_err(|e| e.to_string())?;
    let response = OuterResponse::Raw {
        request: outer,
        signer: signer_id(fingerprint),
        payload,
    };
    match host.accept_response(&response) {
        Ok(QrMusigHostResponse::Prepared(_)) => {
            let record = host
                .record(&session_id)
                .map_err(|e| e.to_string())?
                .ok_or("the prepared session is missing")?;
            store_prepared(root, fingerprint, policy_text, session_id, &record)?;
            Ok(None)
        }
        Ok(QrMusigHostResponse::Signed(returned)) => {
            let sent = sent.ok_or("a signing answer without its request")?;
            accept_signed_at(root, fingerprint, policy_text, &sent, returned).map(Some)
        }
        // A request naming a nonce cache session never gets a round 1 answer.
        Ok(QrMusigHostResponse::PubNonces(_)) => {
            Err("a two-round answer to a nonce cache request".into())
        }
        Err(error) => {
            // The host drops a session the peer refused: its nonces can no longer sign.
            if host
                .record(&session_id)
                .map_err(|e| e.to_string())?
                .is_none()
            {
                drop_session(root, fingerprint, session_id)?;
                return Err(SigningError::SessionLost(error.to_string()));
            }
            Err(SigningError::Invalid(error.to_string()))
        }
    }
}

/// Whether a usable prepared session or an allocation exists for this transaction,
/// read from the in-memory snapshot only.
pub fn qr_ready(fingerprint: Fingerprint, policy_text: &str, real: &Psbt) -> Result<bool, String> {
    let parsed = descriptor(policy_text)?;
    let binding = binding(real, &parsed, fingerprint)?;
    let Some(state) = crate::keys::musig_sessions::snapshot(fingerprint) else {
        return Ok(false);
    };
    if state.is_retired(binding, RouteKind::Qr) {
        return Ok(false);
    }
    if state
        .allocated
        .iter()
        .any(|allocation| allocation.binding == binding && allocation.provider == RouteKind::Qr)
    {
        return Ok(true);
    }
    let infos: Vec<SlotInfo> = slot_infos(real, &parsed)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|info| info.signer.0 == fingerprint)
        .collect();
    if infos.is_empty() {
        return Ok(true);
    }
    for session in &state.available {
        if session.provider != RouteKind::Qr || session.policy != policy_text {
            continue;
        }
        if let Some(qr) = &session.qr {
            if qr.covers(&infos)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Takes the oldest prepared session covering the transaction for this attempt and
/// inserts its nonces. Nothing is visible until the allocation is durable, and a
/// taken session never returns to availability. Idempotent on the active allocation.
pub(crate) fn allocate_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    real: &mut Psbt,
) -> Result<(), SigningError> {
    let parsed = descriptor(policy_text).map_err(|e| e.to_string())?;
    let infos = own_infos(real, &parsed, fingerprint)?;
    let binding = binding(real, &parsed, fingerprint).map_err(|e| e.to_string())?;
    let mut store = LockedCache::open(root, fingerprint).map_err(|e| e.to_string())?;
    if let Some(allocation) = store.active(binding, policy_text, RouteKind::Qr)? {
        if !allocation.covers_slots(&slot_set(&infos)) {
            return Err(lost("MuSig slots changed after cache allocation"));
        }
        if !allocation.compatible_nonces(real, true)? {
            return Err(lost("cached nonces do not match the transaction"));
        }
        return Ok(());
    }
    for info in &infos {
        if musig_input_partial_sig(
            &real.inputs[info.slot.input_index],
            info.slot.participant,
            info.slot.aggregate,
            info.slot.leaf_hash,
        )
        .map_err(|e| e.to_string())?
        .is_some()
        {
            return Err(lost("own partial signature is already present"));
        }
    }
    let mut covering = Vec::new();
    for (index, session) in store.state.available.iter().enumerate() {
        if session.provider != RouteKind::Qr || session.policy != policy_text {
            continue;
        }
        if let Some(qr) = &session.qr {
            if qr.covers(&infos)? {
                covering.push((session.order, index));
            }
        }
    }
    let (_, index) = covering
        .into_iter()
        .min()
        .ok_or_else(|| lost("no prepared QR cache session covers this transaction"))?;
    let mut next = store.state.clone();
    let session = next.available.remove(index);
    let record = session
        .qr
        .as_ref()
        .ok_or_else(|| lost("stored session has no QR record"))?
        .host_record()?;
    let mut published = Vec::new();
    for info in &infos {
        let nonce = record
            .nonces()
            .get(&position(info)?)
            .ok_or_else(|| lost("prepared session does not cover this transaction"))?;
        published.push(PublishedNonce {
            input: info.slot.input_index,
            participant: info.slot.participant,
            aggregate: info.slot.aggregate,
            leaf_hash: info.slot.leaf_hash,
            bytes: nonce.to_vec(),
        });
    }
    let mut published_psbt = real.clone();
    for entry in &published {
        set_musig_input_pub_nonce(
            &mut published_psbt.inputs[entry.input],
            &entry.field().map_err(|e| e.to_string())?,
        );
    }
    store.allocate_transcript(next, session, binding, policy_text, published, None)?;
    *real = published_psbt;
    Ok(())
}

pub fn sign_material(
    fingerprint: Fingerprint,
    policy_text: &str,
    bytes: &[u8],
    routes: &BTreeMap<Fingerprint, RouteKind>,
) -> Result<QrSigningMaterial, SigningError> {
    sign_material_at(
        &datadir().join("musig-sessions"),
        fingerprint,
        policy_text,
        bytes,
        routes,
    )
}

/// A QR signer's first signature request: every pending signer's session taken
/// (`allocate_first_request`), then the host holding this signer's allocated session
/// and the transaction as the request must carry it, every allocated nonce inserted.
pub(crate) fn sign_material_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    bytes: &[u8],
    routes: &BTreeMap<Fingerprint, RouteKind>,
) -> Result<QrSigningMaterial, SigningError> {
    let (qr, request) = qr_first_request_at(root, policy_text, bytes, routes, fingerprint)?;
    let psbt = psbt::parse_v2(&request)
        .map_err(|e| e.to_string())?
        .into_bitcoin_psbt()
        .map_err(|e| e.to_string())?;
    Ok(signing_material(policy_text, &qr, psbt)?)
}

/// The material of a Signing request of `qr`'s session for `psbt`.
fn signing_material(
    policy_text: &str,
    qr: &QrSessionRecord,
    psbt: Psbt,
) -> Result<QrSigningMaterial, String> {
    Ok(QrSigningMaterial {
        host: host([qr])?,
        session_id: qr.session_id,
        descriptor: request::Descriptor {
            alias: hwi::wallet_name(policy_text),
            descriptor: Some(request::DescriptorBody::Bip380(policy_text.to_owned())),
            proof: None,
        },
        psbt,
    })
}

/// Pins the participant nonces of every own slot once every required signer's nonces
/// are in: the transcript the signing answers are held to.
pub(crate) fn pin_transcript_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    real: &Psbt,
) -> Result<(), SigningError> {
    let parsed = descriptor(policy_text).map_err(|e| e.to_string())?;
    let infos = own_infos(real, &parsed, fingerprint)?;
    let binding = binding(real, &parsed, fingerprint).map_err(|e| e.to_string())?;
    let transcript = pinned_transcript(real, &infos)?;
    let mut store = LockedCache::open(root, fingerprint).map_err(|e| e.to_string())?;
    let mut next = store.state.clone();
    let allocation = next
        .allocated
        .iter_mut()
        .find(|allocation| {
            allocation.provider == RouteKind::Qr
                && allocation.binding == binding
                && allocation.state == AllocationState::Active
        })
        .ok_or_else(|| lost("no active cache allocation for this attempt"))?;
    if allocation.qr_transcript.is_some() {
        return Ok(());
    }
    allocation.qr_transcript = Some(transcript);
    store.save(next).map_err(SigningError::from)
}

/// Checks a signing answer the host verified against the allocation and consumes
/// it: the own nonces and the pinned transcript must come back untouched, and the
/// only allowed change to the PSBT `sent` is the own partial signature. Consumed
/// sessions never revive. The signed PSBT comes back without the session field.
pub(crate) fn accept_signed_at(
    root: &Path,
    fingerprint: Fingerprint,
    policy_text: &str,
    sent: &Psbt,
    mut returned: Psbt,
) -> Result<Psbt, SigningError> {
    let parsed = descriptor(policy_text).map_err(|e| e.to_string())?;
    if sent.inputs.len() != returned.inputs.len() {
        return Err("returned input count changed".into());
    }
    let binding = binding(sent, &parsed, fingerprint).map_err(|e| e.to_string())?;
    let mut store = LockedCache::open(root, fingerprint).map_err(|e| e.to_string())?;
    let index = store
        .state
        .allocated
        .iter()
        .position(|allocation| {
            allocation.provider == RouteKind::Qr && allocation.binding == binding
        })
        .ok_or_else(|| lost("no cache allocation for this signing attempt"))?;
    let allocation = store.state.allocated[index].clone();
    if allocation.state != AllocationState::Active {
        return Err(lost("cached signing attempt is no longer active"));
    }
    if allocation.policy != policy_text {
        return Err(lost("cache allocation belongs to another policy"));
    }
    if !allocation.compatible_nonces(&returned, true)? {
        return Err(lost("returned nonces do not match the cache allocation"));
    }
    let infos = own_infos(sent, &parsed, fingerprint)?;
    let pinned = allocation
        .qr_transcript
        .clone()
        .ok_or_else(|| lost("cache allocation has no pinned transcript"))?;
    check_transcript(&returned, &infos, &pinned)?;
    let mut expected = sent.clone();
    let mut consumed = false;
    for info in &infos {
        let signature = musig_input_partial_sig(
            &returned.inputs[info.slot.input_index],
            info.slot.participant,
            info.slot.aggregate,
            info.slot.leaf_hash,
        )
        .map_err(|e| e.to_string())?;
        let Some(signature) = signature else {
            continue;
        };
        set_musig_input_partial_sig(
            &mut expected.inputs[info.slot.input_index],
            &MusigPartialSig {
                participant: info.slot.participant,
                aggregate: info.slot.aggregate,
                leaf_hash: info.slot.leaf_hash,
                signature,
            },
        );
        consumed = true;
    }
    if !consumed {
        return Err("cached signing answer carries no own partial signature".into());
    }
    if expected != returned {
        return Err("unexpected returned PSBT changes".into());
    }
    let mut next = store.state.clone();
    next.allocated[index].state = AllocationState::Consumed;
    store.save(next).map_err(SigningError::from)?;
    returned.unknown.remove(&raw::Key {
        type_value: PSBT_GLOBAL_NONCE_CACHE_SESSION,
        key: Vec::new(),
    });
    Ok(returned)
}

fn own_infos(
    real: &Psbt,
    parsed: &WalletDescriptor,
    fingerprint: Fingerprint,
) -> Result<Vec<SlotInfo>, SigningError> {
    let infos: Vec<SlotInfo> = slot_infos(real, parsed)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|info| info.signer.0 == fingerprint)
        .collect();
    if infos.is_empty() {
        return Err(lost("transaction requests no owned MuSig slots"));
    }
    Ok(infos)
}

fn slot_set(infos: &[SlotInfo]) -> Vec<MusigSlot> {
    infos.iter().map(|info| info.slot).collect()
}

/// One group of concatenated 66-byte participant nonces per own slot, in slot order.
fn pinned_transcript(real: &Psbt, infos: &[SlotInfo]) -> Result<Vec<Vec<u8>>, SigningError> {
    let mut transcript = Vec::new();
    for info in infos {
        let input = &real.inputs[info.slot.input_index];
        let mut group = Vec::new();
        for participant in info.agg.participants() {
            let nonce: [u8; 66] = musig_input_pub_nonce(
                input,
                *participant,
                info.slot.aggregate,
                info.slot.leaf_hash,
            )
            .map_err(|e| e.to_string())?
            .ok_or_else(|| lost("participant nonce is missing for the cached transcript"))?;
            group.extend_from_slice(&nonce);
        }
        transcript.push(group);
    }
    Ok(transcript)
}

/// The returned PSBT must still carry exactly the pinned participant nonces.
fn check_transcript(
    returned: &Psbt,
    infos: &[SlotInfo],
    pinned: &[Vec<u8>],
) -> Result<(), SigningError> {
    if infos.len() != pinned.len() {
        return Err(lost(
            "cache allocation does not match the transaction slots",
        ));
    }
    for (info, group) in infos.iter().zip(pinned.iter()) {
        if group.len() != info.agg.participants().len() * 66 || group.len() % 66 != 0 {
            return Err(lost("returned participant transcript changed"));
        }
        let input = &returned.inputs[info.slot.input_index];
        for (participant, nonce) in info.agg.participants().iter().zip(group.chunks_exact(66)) {
            let pinned_nonce: [u8; 66] = nonce
                .try_into()
                .map_err(|_| lost("invalid pinned nonce length"))?;
            let found = musig_input_pub_nonce(
                input,
                *participant,
                info.slot.aggregate,
                info.slot.leaf_hash,
            )
            .map_err(|e| e.to_string())?;
            if found != Some(pinned_nonce) {
                return Err(lost("returned participant transcript changed"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use bipqr::ll::{decode, encode_response, response, types, Message, Response};
    use bitcoin::{
        absolute::LockTime,
        bip32::{DerivationPath, Fingerprint},
        psbt::raw,
        transaction::Version,
        Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    };
    use bwk::{
        bwk_descriptor::{
            updater::update_input,
            wallet::{WalletDescriptor, WalletDescriptorExt},
        },
        bwk_sign::{
            hot_signer::HotSigner,
            musig::own_slots,
            qr_musig::{encode_record, encode_registered, QrMusigPeer, QrMusigPeerRecord},
        },
        bwk_tx::bwk_psbt::{
            musig::{musig_input_partial_sigs, musig_input_pub_nonce},
            nonce_cache::PSBT_GLOBAL_NONCE_CACHE_SESSION,
            PsbtV2,
        },
        persist::{backend::noop::NoopBackend, storage::ram::RamStore},
    };
    use temp_dir::TempDir;

    use crate::keys::{
        musig_sessions::{
            descriptor,
            hot_provider::{create_locked, first_request_at},
            qr_first_request_at,
            qr_provider::{
                accept_answer_at, allocate_at, pin_transcript_at, prepare_material_at, qr_ready,
                signing_material, QrMusigAnswer,
            },
            start_attempt, AllocationState, LockedCache, SigningError, MAX_INPUT,
        },
        qr::{QrRequest, QrResponse, QrSession},
        record::RouteKind,
    };

    const MNEMONIC_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const MNEMONIC_B: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    // The readiness case reads the process-wide snapshot: its device is its own.
    const MNEMONIC_C: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    type Peer = QrMusigPeer<
        RamStore<NoopBackend, [u8; 4], QrMusigPeerRecord>,
        RamStore<NoopBackend, String, WalletDescriptor>,
    >;

    /// The QR device of signer A: bwk's QR MuSig peer, its sessions in memory.
    fn peer(signer: &HotSigner) -> Peer {
        QrMusigPeer::from_store(
            signer.clone(),
            RamStore::empty(
                NoopBackend::new(),
                "sessions",
                |session_id| hex::encode(session_id),
                |record| Ok(encode_record(record)),
            ),
            RamStore::empty(
                NoopBackend::new(),
                "registry",
                |alias| alias.clone(),
                |descriptor| Ok(encode_registered(descriptor)),
            ),
        )
    }

    struct Fixture {
        root: TempDir,
        a: HotSigner,
        b: HotSigner,
        fingerprint: Fingerprint,
        policy: String,
    }

    /// Signer A is the QR device, B the cosigner: aggregate then derive, as Silent's
    /// accounts.
    fn fixture() -> Fixture {
        fixture_on(MNEMONIC_A)
    }

    fn fixture_on(device: &str) -> Fixture {
        let a = HotSigner::new_from_mnemonics(Network::Regtest, device).expect("signer a");
        let b = HotSigner::new_from_mnemonics(Network::Regtest, MNEMONIC_B).expect("signer b");
        let path = DerivationPath::from_str("m/87'/1'/0'").expect("account path");
        let policy = format!(
            "tr(musig([{}/87h/1h/0h]{},[{}/87h/1h/0h]{})/<0;1>/*)",
            a.fingerprint(),
            a.xpub(&path).xkey,
            b.fingerprint(),
            b.xpub(&path).xkey
        );
        let fingerprint = a.fingerprint();
        Fixture {
            root: TempDir::new().expect("temp directory"),
            a,
            b,
            fingerprint,
            policy,
        }
    }

    impl Fixture {
        fn root(&self) -> &std::path::Path {
            self.root.path()
        }

        fn parsed(&self) -> WalletDescriptor {
            descriptor(&self.policy).expect("policy")
        }

        fn cache(&self) -> LockedCache {
            LockedCache::open(self.root(), self.fingerprint).expect("open cache")
        }
    }

    /// A transaction spending `inputs` outputs of the policy's address `index`.
    fn transaction(policy: &str, index: u32, inputs: usize) -> Psbt {
        let parsed = descriptor(policy).expect("policy");
        let definite = parsed.single_paths().expect("paths")[0]
            .derive_at(index)
            .expect("derive address");
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..inputs)
                .map(|vout| TxIn {
                    previous_output: OutPoint {
                        vout: vout as u32,
                        ..OutPoint::null()
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Default::default(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: definite.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("PSBT");
        for input in 0..inputs {
            psbt.inputs[input].witness_utxo = Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: definite.script_pubkey(),
            });
            update_input(&mut psbt, input, &definite).expect("input metadata");
        }
        psbt
    }

    /// The peer's answer to `request`, decoded against the session that asked it.
    fn exchange(peer: &mut Peer, session: &mut QrSession, request: QrRequest) -> QrResponse {
        session
            .decode_response(&answer_bytes(peer, &request))
            .expect("decode the answer")
    }

    fn answer_bytes(peer: &mut Peer, request: &QrRequest) -> Vec<u8> {
        let Message::Request(request) = decode(request.message()).expect("decode the request")
        else {
            panic!("expected a request");
        };
        encode_response(&peer.handle(request)).expect("encode the answer")
    }

    fn musig_answer(response: QrResponse) -> QrMusigAnswer {
        match response {
            QrResponse::MusigPrepared(answer) | QrResponse::MusigSignedPsbt(answer) => answer,
            other => panic!("expected a nonce cache answer, got {other:?}"),
        }
    }

    /// Runs one nonce preparation through the peer, as the GUI engine does.
    fn prepare(fixture: &Fixture, peer: &mut Peer) -> [u8; 4] {
        let material = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare material");
        let session_id = material.session_id;
        let mut session = QrSession::new();
        let request = session.prepare_nonces(material).expect("prepare request");
        let answer = musig_answer(exchange(peer, &mut session, request));
        let accepted =
            accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer)
                .expect("accept the preparation");
        assert!(accepted.is_none(), "a preparation returns no PSBT");
        session_id
    }

    /// Signs `tx` with the session its QR allocation took, through the peer.
    fn sign(fixture: &Fixture, peer: &mut Peer, tx: &Psbt) -> Result<Option<Psbt>, SigningError> {
        let mut session = QrSession::new();
        let request = session
            .sign_nonce_cache(allocated_material(fixture, tx))
            .expect("signing request");
        let answer = musig_answer(exchange(peer, &mut session, request));
        accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer)
    }

    fn allocated_material(
        fixture: &Fixture,
        tx: &Psbt,
    ) -> crate::keys::musig_sessions::QrSigningMaterial {
        let store = fixture.cache();
        let qr = store
            .state
            .allocated
            .last()
            .and_then(|allocation| allocation.qr.clone())
            .expect("a QR allocation");
        signing_material(&fixture.policy, &qr, tx.clone()).expect("signing material")
    }

    /// Allocates `tx` to the prepared session, adds the cosigner's nonces and pins
    /// the transcript: what the first signature request leaves behind.
    fn allocated(fixture: &Fixture, mut tx: Psbt) -> Psbt {
        allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut tx,
        )
        .expect("allocate");
        fixture
            .b
            .inner_sign(&mut tx, &fixture.parsed())
            .expect("cosigner nonces");
        pin_transcript_at(fixture.root(), fixture.fingerprint, &fixture.policy, &tx).expect("pin");
        tx
    }

    fn session_field() -> raw::Key {
        raw::Key {
            type_value: PSBT_GLOBAL_NONCE_CACHE_SESSION,
            key: Vec::new(),
        }
    }

    #[test]
    fn prepare_persists_a_public_record_and_reuses_its_session_id() {
        let fixture = fixture();
        let material = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare material");
        assert_eq!(
            material.issuance.path,
            DerivationPath::from_str("m/87'/1'/0'").expect("path"),
            "the nonces of the participant key"
        );
        assert_eq!(
            (
                material.issuance.max_inputs,
                material.issuance.start,
                material.issuance.end
            ),
            (MAX_INPUT as u32, 0, 0),
            "every input position of the one key expression"
        );
        let store = fixture.cache();
        assert_eq!(
            store.state.available.len(),
            1,
            "one preparation record persisted"
        );
        let session = &store.state.available[0];
        assert_eq!(session.provider, RouteKind::Qr, "QR provider record");
        assert!(
            session.secret.is_none() && session.fetched_for.is_none(),
            "no secret material and no transaction binding on a QR record"
        );
        let qr = session.qr.as_ref().expect("QR record");
        assert_eq!(qr.session_id, material.session_id, "session id carried");
        let record = qr.host_record().expect("host record");
        assert!(
            record.nonces().is_empty() && record.session_ref().is_none(),
            "nothing stored before the answer"
        );
        drop(store);
        let again = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare again");
        assert_eq!(
            again.session_id, material.session_id,
            "the available preparation is reused, never duplicated"
        );
    }

    #[test]
    fn a_policy_whose_participant_changes_with_the_address_is_refused() {
        let fixture = fixture();
        let path = DerivationPath::from_str("m/87'/1'/0'").expect("account path");
        let derived = format!(
            "tr(musig([{}/87h/1h/0h]{}/<0;1>/*,[{}/87h/1h/0h]{}/<0;1>/*))",
            fixture.a.fingerprint(),
            fixture.a.xpub(&path).xkey,
            fixture.b.fingerprint(),
            fixture.b.xpub(&path).xkey
        );
        assert!(
            prepare_material_at(fixture.root(), fixture.fingerprint, &derived).is_err(),
            "one issuance cannot cover a participant key that changes with the address"
        );
        assert!(
            fixture.cache().state.available.is_empty(),
            "nothing persisted"
        );
    }

    #[test]
    fn accept_prepared_stores_the_issued_nonces_once() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        let session_id = prepare(&fixture, &mut peer);
        let record = fixture.cache().state.available[0]
            .qr
            .as_ref()
            .expect("QR record")
            .host_record()
            .expect("host record");
        assert_eq!(
            record.nonces().len(),
            MAX_INPUT,
            "one nonce per input position"
        );
        assert!(record.session_ref().is_some(), "the peer's reference");
        assert_eq!(
            prepare(&fixture, &mut peer),
            session_id,
            "asking the same session again is idempotent"
        );
        assert_eq!(
            fixture.cache().state.available.len(),
            1,
            "still one session"
        );
    }

    #[test]
    fn an_answer_for_another_session_is_refused_and_the_exchange_stays_open() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        let material = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare material");
        let mut session = QrSession::new();
        let request = session.prepare_nonces(material).expect("prepare request");
        let honest = answer_bytes(&mut peer, &request);
        let Message::Response(mut stranger) = decode(&honest).expect("decode") else {
            panic!("expected a response");
        };
        let response::Body::NoncesPrepared(prepared) = &mut stranger.body else {
            panic!("expected prepared nonces");
        };
        prepared
            .session
            .as_mut()
            .expect("the answer announces the new session")
            .session_id = [9; 4];
        assert!(
            matches!(
                session.decode_response(&encode_response(&stranger).expect("encode")),
                Err(crate::keys::Error::MusigSessionMismatch)
            ),
            "an answer for another session is refused before the host"
        );
        let answer = musig_answer(
            session
                .decode_response(&honest)
                .expect("the exchange stays open after a refusal"),
        );
        accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer)
            .expect("the honest answer is accepted");
        let record = fixture.cache().state.available[0]
            .qr
            .as_ref()
            .expect("QR record")
            .host_record()
            .expect("host record");
        assert_eq!(
            record.nonces().len(),
            MAX_INPUT,
            "the honest nonces are stored"
        );
    }

    #[test]
    fn a_late_answer_without_its_record_is_refused() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        let material = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare material");
        let mut session = QrSession::new();
        let request = session.prepare_nonces(material).expect("prepare request");
        let answer = musig_answer(exchange(&mut peer, &mut session, request));
        {
            let mut store = fixture.cache();
            let mut next = store.state.clone();
            next.available.clear();
            store.save(next).expect("drop the record");
        }
        let error = accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer)
            .expect_err("no preparation is in flight");
        assert!(
            error.to_string().contains("no preparation in flight"),
            "a late answer without its record is refused, got {error}"
        );
    }

    #[test]
    fn a_session_the_peer_lost_is_forgotten() {
        let fixture = fixture();
        prepare(&fixture, &mut peer(&fixture.a));
        // Another device with the same seed holds no session: it refuses the reference.
        let mut forgetful = peer(&fixture.a);
        let material = prepare_material_at(fixture.root(), fixture.fingerprint, &fixture.policy)
            .expect("prepare material");
        let mut session = QrSession::new();
        let request = session.prepare_nonces(material).expect("prepare request");
        let answer = musig_answer(exchange(&mut forgetful, &mut session, request));
        let error = accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer)
            .expect_err("the peer refused the session");
        assert!(
            matches!(error, SigningError::SessionLost(_)),
            "a refusal for the session loses it, got {error}"
        );
        assert!(
            fixture.cache().state.available.is_empty(),
            "the lost session is no longer available"
        );
    }

    #[test]
    fn qr_ready_reflects_coverage_and_allocation() {
        let fixture = fixture_on(MNEMONIC_C);
        let tx = transaction(&fixture.policy, 0, 1);
        assert!(
            !qr_ready(fixture.fingerprint, &fixture.policy, &tx).expect("empty readiness"),
            "an empty cache is not ready"
        );
        prepare(&fixture, &mut peer(&fixture.a));
        assert!(
            qr_ready(fixture.fingerprint, &fixture.policy, &tx).expect("prepared readiness"),
            "a prepared session covering the transaction is ready"
        );
        assert!(
            qr_ready(
                fixture.fingerprint,
                &fixture.policy,
                &transaction(&fixture.policy, 90, 1)
            )
            .expect("any address readiness"),
            "one issuance covers every address"
        );
        let outside = transaction(&fixture.policy, 0, MAX_INPUT + 1);
        assert!(
            !qr_ready(fixture.fingerprint, &fixture.policy, &outside).expect("coverage readiness"),
            "a transaction beyond the input coverage is not ready"
        );
        let mut allocated = tx.clone();
        allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut allocated,
        )
        .expect("allocate");
        assert!(
            qr_ready(fixture.fingerprint, &fixture.policy, &tx).expect("allocated readiness"),
            "an active allocation keeps the attempt ready"
        );
    }

    #[test]
    fn allocation_is_durable_fifo_and_never_returns_to_available() {
        let fixture = fixture();
        prepare(&fixture, &mut peer(&fixture.a));
        {
            let mut store = fixture.cache();
            let mut next = store.state.clone();
            let mut second = next.available[0].clone();
            second.id = [2; 32];
            second.order = 0;
            next.available.insert(0, second);
            store.save(next).expect("prepend an older session");
        }
        let mut tx = transaction(&fixture.policy, 0, 1);
        allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut tx,
        )
        .expect("allocate");
        let store = fixture.cache();
        assert_eq!(
            store.state.allocated.len(),
            1,
            "exactly one allocation is on disk"
        );
        let allocation = &store.state.allocated[0];
        assert_eq!(
            allocation.id, [2; 32],
            "the oldest session is taken, whatever its id"
        );
        assert_eq!(
            allocation.provider,
            RouteKind::Qr,
            "the allocation belongs to the QR provider"
        );
        assert!(
            allocation.secret.is_none(),
            "a QR allocation never carries secret material"
        );
        assert!(
            allocation.qr.is_some(),
            "the allocation keeps the peer's session record"
        );
        assert!(
            allocation.qr_transcript.is_none(),
            "the transcript is pinned separately, after every signer is in"
        );
        assert_eq!(
            store.state.available.len(),
            1,
            "only the remaining session stays available"
        );
        drop(store);
        allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut tx,
        )
        .expect("a retry reuses the active allocation");
        let store = fixture.cache();
        assert_eq!(
            (store.state.allocated.len(), store.state.available.len()),
            (1, 1),
            "a retry never takes another session"
        );
    }

    #[test]
    fn allocation_refuses_uncovered_transactions() {
        let fixture = fixture();
        prepare(&fixture, &mut peer(&fixture.a));
        let mut outside = transaction(&fixture.policy, 0, MAX_INPUT + 1);
        let error = allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut outside,
        )
        .expect_err("beyond the input coverage");
        assert!(
            matches!(error, SigningError::SessionLost(_)),
            "an uncovered transaction must not take a session, got {error}"
        );
        let store = fixture.cache();
        assert!(
            store.state.allocated.is_empty(),
            "nothing was allocated for an uncovered transaction"
        );
        assert_eq!(
            store.state.available.len(),
            1,
            "the session stayed available"
        );
    }

    #[test]
    fn pin_requires_every_participant_and_the_signing_answer_consumes() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        prepare(&fixture, &mut peer);
        let mut tx = transaction(&fixture.policy, 0, 1);
        allocate_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            &mut tx,
        )
        .expect("allocate");
        assert!(
            pin_transcript_at(fixture.root(), fixture.fingerprint, &fixture.policy, &tx).is_err(),
            "an incomplete nonce set is not pinned"
        );
        fixture
            .b
            .inner_sign(&mut tx, &fixture.parsed())
            .expect("cosigner nonces");
        pin_transcript_at(fixture.root(), fixture.fingerprint, &fixture.policy, &tx)
            .expect("pin once every participant is in");
        assert!(
            fixture.cache().state.allocated[0].qr_transcript.is_some(),
            "the pinned transcript is durable"
        );

        let material = allocated_material(&fixture, &tx);
        let signed = sign(&fixture, &mut peer, &tx)
            .expect("accept the signing answer")
            .expect("the signed PSBT");
        assert_eq!(
            musig_input_partial_sigs(&signed.inputs[0])
                .expect("partial signatures")
                .len(),
            1,
            "the device's partial signature is in"
        );
        assert!(
            !signed.unknown.contains_key(&session_field()),
            "the session field does not leave the exchange"
        );
        assert_eq!(
            fixture.cache().state.allocated[0].state,
            AllocationState::Consumed,
            "a verified answer consumes the allocation"
        );

        // The peer deleted the session when it signed: asking again is refused.
        let mut session = QrSession::new();
        let request = session.sign_nonce_cache(material).expect("signing request");
        let answer = musig_answer(exchange(&mut peer, &mut session, request));
        assert!(
            matches!(
                accept_answer_at(fixture.root(), fixture.fingerprint, &fixture.policy, answer),
                Err(SigningError::SessionLost(_))
            ),
            "a session never signs twice"
        );
    }

    #[test]
    fn an_answer_changing_the_transaction_is_refused() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        prepare(&fixture, &mut peer);
        let mut tx = transaction(&fixture.policy, 0, 1);
        start_attempt(&mut tx).expect("attempt id");
        let tx = allocated(&fixture, tx);
        let mut session = QrSession::new();
        let request = session
            .sign_nonce_cache(allocated_material(&fixture, &tx))
            .expect("signing request");
        let Message::Response(mut answer) =
            decode(&answer_bytes(&mut peer, &request)).expect("decode")
        else {
            panic!("expected a response");
        };
        let response::Body::Signed(response::Signed::Psbt(bytes)) = &mut answer.body else {
            panic!("expected a signed PSBT");
        };
        let mut tampered = Psbt::deserialize(bytes).expect("signed PSBT");
        tampered.unsigned_tx.output[0].value = Amount::from_sat(89_999);
        *bytes = tampered.serialize();
        let decoded = session
            .decode_response(&encode_response(&answer).expect("encode"))
            .expect("decode the answer");
        assert!(
            matches!(
                accept_answer_at(
                    fixture.root(),
                    fixture.fingerprint,
                    &fixture.policy,
                    musig_answer(decoded)
                ),
                Err(SigningError::Invalid(_))
            ),
            "an answer changing the transaction is refused"
        );
        assert_eq!(
            fixture.cache().state.allocated[0].state,
            AllocationState::Active,
            "a refused answer leaves the allocation active"
        );
    }

    #[test]
    fn a_signatures_only_answer_is_verified_and_merged() {
        let fixture = fixture();
        let mut peer = peer(&fixture.a);
        prepare(&fixture, &mut peer);
        let tx = allocated(&fixture, transaction(&fixture.policy, 0, 1));
        let mut session = QrSession::new();
        let request = session
            .sign_nonce_cache(allocated_material(&fixture, &tx))
            .expect("signing request");
        let Message::Response(answer) = decode(&answer_bytes(&mut peer, &request)).expect("decode")
        else {
            panic!("expected a response");
        };
        let response::Body::Signed(response::Signed::Psbt(bytes)) = &answer.body else {
            panic!("expected a signed PSBT");
        };
        let partial =
            musig_input_partial_sigs(&Psbt::deserialize(bytes).expect("signed PSBT").inputs[0])
                .expect("partial signatures")
                .remove(0);
        let entry = |signature| response::SignatureEntry::MusigPartialSig {
            input_index: 0,
            participant: types::PublicKey(partial.participant.serialize()),
            aggregate: types::PublicKey(partial.aggregate.serialize()),
            leaf_hash: None,
            signature,
        };
        let reply = |signature| {
            encode_response(&Response {
                id: answer.id,
                body: response::Body::Signed(response::Signed::Signatures(vec![entry(signature)])),
            })
            .expect("encode")
        };

        let mut forged = partial.signature;
        forged[31] ^= 1;
        let mut forged_session = QrSession::new();
        let forged_request = forged_session
            .sign_nonce_cache(allocated_material(&fixture, &tx))
            .expect("signing request");
        let mut forged_reply = decode(&reply(forged)).expect("decode");
        if let Message::Response(response) = &mut forged_reply {
            response.id = forged_request.id();
        }
        let Message::Response(forged_reply) = forged_reply else {
            panic!("expected a response");
        };
        let decoded = forged_session
            .decode_response(&encode_response(&forged_reply).expect("encode"))
            .expect("decode");
        assert!(
            matches!(
                accept_answer_at(
                    fixture.root(),
                    fixture.fingerprint,
                    &fixture.policy,
                    musig_answer(decoded)
                ),
                Err(SigningError::Invalid(_))
            ),
            "a partial signature that does not verify is refused"
        );
        assert_eq!(
            fixture.cache().state.allocated[0].state,
            AllocationState::Active,
            "a refused answer leaves the allocation active"
        );

        let decoded = session
            .decode_response(&reply(partial.signature))
            .expect("decode");
        let signed = accept_answer_at(
            fixture.root(),
            fixture.fingerprint,
            &fixture.policy,
            musig_answer(decoded),
        )
        .expect("a verified signatures-only answer")
        .expect("the signed PSBT");
        assert_eq!(
            musig_input_partial_sigs(&signed.inputs[0]).expect("partial signatures"),
            vec![partial],
            "the partial signature is merged into the sent PSBT"
        );
        assert_eq!(
            fixture.cache().state.allocated[0].state,
            AllocationState::Consumed,
            "the verified answer consumes the allocation"
        );
    }

    fn v2(tx: Psbt) -> Vec<u8> {
        PsbtV2::from_bitcoin_psbt(tx)
            .expect("v2")
            .serialize()
            .expect("serialize")
    }

    fn routes(fixture: &Fixture) -> BTreeMap<Fingerprint, RouteKind> {
        BTreeMap::from([
            (fixture.fingerprint, RouteKind::Qr),
            (fixture.b.fingerprint(), RouteKind::Hot),
        ])
    }

    fn cosigner_hot_session(fixture: &Fixture, id: u8) {
        let mut store =
            LockedCache::open(fixture.root(), fixture.b.fingerprint()).expect("cosigner cache");
        create_locked(&mut store, &fixture.b, &fixture.policy, [id; 32], None)
            .expect("cosigner hot session");
    }

    fn carries_every_nonce(fixture: &Fixture, tx: &Psbt) -> bool {
        let parsed = fixture.parsed();
        [fixture.fingerprint, fixture.b.fingerprint()]
            .into_iter()
            .all(|signer| {
                let slots = own_slots(tx, &parsed, signer).expect("own slots");
                !slots.is_empty()
                    && slots.iter().all(|slot| {
                        musig_input_pub_nonce(
                            &tx.inputs[slot.input_index],
                            slot.participant,
                            slot.aggregate,
                            slot.leaf_hash,
                        )
                        .expect("nonce field")
                        .is_some()
                    })
            })
    }

    #[test]
    fn allocate_first_request_binds_every_required_signer() {
        let fixture = fixture();
        let session_id = prepare(&fixture, &mut peer(&fixture.a));
        cosigner_hot_session(&fixture, 80);
        let mut tx = transaction(&fixture.policy, 0, 1);
        start_attempt(&mut tx).expect("attempt id");
        let (qr, request) = qr_first_request_at(
            fixture.root(),
            &fixture.policy,
            &v2(tx),
            &routes(&fixture),
            fixture.fingerprint,
        )
        .expect("first request allocation");
        assert_eq!(qr.session_id, session_id, "the prepared session is taken");
        let allocated = PsbtV2::deserialize(&request)
            .expect("v2")
            .into_bitcoin_psbt()
            .expect("v0");
        assert!(
            carries_every_nonce(&fixture, &allocated),
            "every required signer's nonces ride on the request"
        );
        assert!(
            LockedCache::open(fixture.root(), fixture.b.fingerprint())
                .expect("cosigner cache")
                .state
                .available
                .is_empty(),
            "the hot session was taken for this attempt"
        );
        assert!(
            fixture.cache().state.allocated[0].qr_transcript.is_some(),
            "the transcript is pinned in the same pass"
        );
    }

    #[test]
    fn a_hot_first_request_takes_the_qr_signers_prepared_session_and_pins_it() {
        let fixture = fixture();
        prepare(&fixture, &mut peer(&fixture.a));
        cosigner_hot_session(&fixture, 81);
        let mut tx = transaction(&fixture.policy, 0, 1);
        start_attempt(&mut tx).expect("attempt id");
        assert!(
            first_request_at(
                fixture.root(),
                fixture.b.fingerprint(),
                &fixture.policy,
                &mut tx,
                &routes(&fixture),
                None,
            )
            .expect("hot first request"),
            "the hot key's cached session crafts the request"
        );
        assert!(
            carries_every_nonce(&fixture, &tx),
            "the hot request carries every signer's nonces"
        );
        let store = fixture.cache();
        assert!(
            store.state.available.is_empty(),
            "the QR preparation was taken by the hot request"
        );
        assert_eq!(
            store.state.allocated[0].state,
            AllocationState::Active,
            "the QR session is bound to this attempt"
        );
        assert!(
            store.state.allocated[0].qr_transcript.is_some(),
            "the QR transcript is pinned in the same pass"
        );
    }

    #[test]
    fn allocate_first_request_fails_without_touching_any_cache_when_a_signer_is_not_ready() {
        let fixture = fixture();
        prepare(&fixture, &mut peer(&fixture.a));
        // The cosigner has no hot session: the whole pass must refuse.
        let mut tx = transaction(&fixture.policy, 0, 1);
        start_attempt(&mut tx).expect("attempt id");
        assert!(
            qr_first_request_at(
                fixture.root(),
                &fixture.policy,
                &v2(tx),
                &routes(&fixture),
                fixture.fingerprint,
            )
            .is_err(),
            "a required signer without a cached session fails the request"
        );
        let store = fixture.cache();
        assert!(
            store.state.allocated.is_empty(),
            "the QR session was not taken by a failed request"
        );
        assert_eq!(
            store.state.available.len(),
            1,
            "the preparation stayed available"
        );
    }
}
