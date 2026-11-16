//! The nonce cache MuSig QR exchange through the module: the material step persists
//! the record, the request is issued, bwk's QR MuSig peer answers it, and the decoded
//! answer lands in the cache as a prepared session. These are the exact module
//! functions the GUI engine's worker and slots call, in the same order.

use std::str::FromStr;
use std::sync::OnceLock;

use bipqr::ll::{decode, encode_response, request, response, Message, Request};
use bitcoin::{
    absolute::LockTime, bip32::DerivationPath, hashes::Hash, transaction::Version, Amount,
    OutPoint, Transaction, TxIn, TxOut, Txid,
};
use bwk::{
    account::Account as BwkAccount,
    bwk_descriptor::wallet::WalletDescriptor,
    bwk_sign::{
        hot_signer::HotSigner,
        qr_musig::{encode_record, encode_registered, QrMusigPeer, QrMusigPeerRecord},
    },
    persist::{backend::noop::NoopBackend, storage::ram::RamStore},
};
use reckless::{
    Config, KeyRouteKind, MusigAccount, Network as FfiNetwork, Output, TransactionTemplate,
};

// ===== Datadir =====

static DATADIR: OnceLock<temp_dir::TempDir> = OnceLock::new();

fn datadir() -> &'static std::path::Path {
    DATADIR
        .get_or_init(|| {
            let tmp = temp_dir::TempDir::new().expect("create temp dir");
            reckless::set_datadir(tmp.path().to_path_buf());
            reckless::state_crypt::unlock_for_tests();
            tmp
        })
        .path()
}

// ===== Fixtures =====

const MNEMONIC_A: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_B: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
// A second pair, so a case's cache never mixes with another case's fingerprint.
const MNEMONIC_C: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const MNEMONIC_D: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
// A third pair for the attempt case, whose cache must not mix with the exchanges'.
const MNEMONIC_E: &str =
    "cancel animal embark drastic bamboo mountain loyal category cancel animal embark dress";
const MNEMONIC_F: &str = "captain baby mass dust captain baby mass dust captain baby mass dutch";

fn signers() -> (HotSigner, HotSigner) {
    signers_on(MNEMONIC_A, MNEMONIC_B)
}

fn signers_on(a: &str, b: &str) -> (HotSigner, HotSigner) {
    (
        HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, a).expect("signer a"),
        HotSigner::new_from_mnemonics(bitcoin::Network::Regtest, b).expect("signer b"),
    )
}

/// The descriptor an account is opened with: the exact policy string the cache
/// sessions and the first signature request must share.
fn account_policy(a: &HotSigner, b: &HotSigner) -> String {
    let path = DerivationPath::from_str("m/87'/1'/0'").expect("account path");
    format!(
        "tr(musig([{}/87h/1h/0h]{},[{}/87h/1h/0h]{})/<0;1>/*)",
        a.fingerprint(),
        a.xpub(&path).xkey,
        b.fingerprint(),
        b.xpub(&path).xkey
    )
}

type Peer = QrMusigPeer<
    RamStore<NoopBackend, [u8; 4], QrMusigPeerRecord>,
    RamStore<NoopBackend, String, WalletDescriptor>,
>;

/// A QR device: bwk's QR MuSig peer on `signer`, its sessions in memory.
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

fn wire_request(payload: &[u8]) -> Request {
    match decode(payload).expect("decode the wire request") {
        Message::Request(request) => request,
        Message::Response(_) => panic!("expected a request, decoded a response"),
    }
}

/// The peer's encoded answer to the wire request it was shown.
fn answer(peer: &mut Peer, payload: &[u8]) -> Vec<u8> {
    encode_response(&peer.handle(wire_request(payload))).expect("encode the peer's answer")
}

// ===== The exchange =====

#[test]
fn cached_prepare_exchange_issues_the_request_and_delivers_the_answer() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers();
    let policy = account_policy(&a, &b);
    let fingerprint = a.fingerprint().to_string();
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);

    // The worker step: the record is persisted, the material handed back.
    let material = reckless::qr_musig_prepare_material(&fingerprint, &policy);
    // The slot step: the wire request is built and made the outstanding one.
    let message = module.qr_request_prepare_musig(material);
    assert!(
        message.is_ok,
        "the prepare request is issued: {}",
        message.error
    );
    let request::Body::PrepareNonces(preparation) = wire_request(&message.payload).body else {
        panic!("expected a PrepareNonces request");
    };
    assert_eq!(
        (preparation.max_inputs, preparation.start, preparation.end),
        (8, 0, Some(0)),
        "every input position of the signer's one key expression"
    );
    assert!(
        preparation.session_ref.is_none(),
        "a fresh session names no reference"
    );

    // The device answers the request it was shown; the engine decodes against the
    // outstanding request and hands the result to the cache.
    let decoded = module.qr_decode_response(&answer(&mut peer(&a), &message.payload));
    assert!(
        decoded.is_ok(),
        "the peer's answer decodes: {}",
        decoded.get_error()
    );
    assert_eq!(
        decoded.kind(),
        reckless::QrResponseKind::MusigPrepared,
        "a prepared answer is recognized as its own kind"
    );
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(accepted.is_ok, "the answer is accepted: {}", accepted.error);
    assert_eq!(
        reckless::musig_session_count(&fingerprint, &policy, KeyRouteKind::Qr),
        1,
        "the cache holds exactly the prepared session"
    );
}

#[test]
fn an_answer_for_another_session_is_refused_before_the_cache() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_C, MNEMONIC_D);
    let policy = account_policy(&a, &b);
    let fingerprint = a.fingerprint().to_string();
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);

    let material = reckless::qr_musig_prepare_material(&fingerprint, &policy);
    let message = module.qr_request_prepare_musig(material);
    assert!(message.is_ok, "the prepare request is issued");

    let honest = answer(&mut peer(&a), &message.payload);
    let Message::Response(mut stranger) = decode(&honest).expect("decode the answer") else {
        panic!("expected a response");
    };
    let response::Body::NoncesPrepared(prepared) = &mut stranger.body else {
        panic!("expected prepared nonces");
    };
    prepared
        .session
        .as_mut()
        .expect("the answer announces the new session")
        .session_id = [0xab; 4];
    let decoded =
        module.qr_decode_response(&encode_response(&stranger).expect("encode the stranger"));
    assert!(
        !decoded.is_ok(),
        "an answer for another session is refused by the codec"
    );

    // The refusal consumed nothing: the right answer still prepares the session.
    let decoded = module.qr_decode_response(&honest);
    assert!(
        decoded.is_ok(),
        "the exchange stays open after a refusal: {}",
        decoded.get_error()
    );
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(
        accepted.is_ok,
        "the honest answer is accepted: {}",
        accepted.error
    );
    assert_eq!(
        reckless::musig_session_count(&fingerprint, &policy, KeyRouteKind::Qr),
        1,
        "the cache holds exactly the prepared session"
    );
}

// ===== The attempt =====

/// A funded two-key musig account with a prepared one-input transaction, so the
/// active attempt is exactly what a first signature request allocates against.
struct FundedAttempt {
    config: Box<Config>,
    account: Box<MusigAccount>,
}

impl FundedAttempt {
    fn new(policy: &str) -> Self {
        Self::named(policy, "attempt")
    }

    /// A config of its own name, for a case running beside the others.
    fn named(policy: &str, tag: &str) -> Self {
        assert!(
            reckless::validate_musig_descriptor(policy.to_string()).is_ok,
            "the account policy is accepted"
        );
        let name = format!("qr_cache_{tag}_{}", std::process::id());
        let config = reckless::new_config(
            name.clone(),
            FfiNetwork::Regtest,
            policy.to_string(),
            String::new(),
            String::new(),
            0,
            "musig".into(),
        );
        assert!(config.save().is_empty(), "save the account config");
        let mut backend: BwkAccount =
            BwkAccount::try_new(config.to_musig_config().expect("backend config"))
                .expect("backend");
        let address = backend.scanner_mut().new_recv_addr();
        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([7; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        backend.scanner().record_unconfirmed_spend(&funding);
        drop(backend);
        let mut account = reckless::new_musig_account(name);
        assert!(account.is_ok(), "open the account: {}", account.get_error());
        let outpoint = OutPoint::new(funding.compute_txid(), 0).to_string();
        let paths = account.spend_leaves(vec![outpoint.clone()]);
        assert!(paths.is_ok, "spend paths: {}", paths.error);
        assert_eq!(paths.leaves.len(), 1, "one selectable path");
        let recipient = account.new_addr();
        let template = TransactionTemplate {
            outputs: vec![Output {
                address: recipient,
                amount: 40_000,
                label: String::new(),
                max: false,
            }],
            fee: 1000,
            fee_rate: 0.0,
            input_outpoints: vec![outpoint],
        };
        let psbt = account.finalize_transaction(template.clone());
        assert!(psbt.is_ok, "finalize the attempt: {}", psbt.error);
        let prepared = account.adopt_transaction(template, paths.leaves[0].clone(), &psbt.psbt);
        assert!(
            prepared.is_ok(),
            "prepare the attempt: {}",
            prepared.get_psbt_error()
        );
        Self { config, account }
    }

    fn finish(self) {
        let name = self.config.account_name.clone();
        drop(self.account);
        reckless::delete_config(name);
    }
}

/// Runs the nonce preparation exchange for one device, in the order the GUI engine's
/// worker and slots call the module functions.
fn prepare_cached_session(
    module: &mut reckless::KeysModule,
    device: &mut Peer,
    signer: &HotSigner,
    policy: &str,
) {
    let fingerprint = signer.fingerprint().to_string();
    let material = reckless::qr_musig_prepare_material(&fingerprint, policy);
    let message = module.qr_request_prepare_musig(material);
    assert!(
        message.is_ok,
        "the prepare request is issued: {}",
        message.error
    );
    let decoded = module.qr_decode_response(&answer(device, &message.payload));
    assert!(
        decoded.is_ok(),
        "the peer's answer decodes: {}",
        decoded.get_error()
    );
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, policy);
    assert!(accepted.is_ok, "the answer is accepted: {}", accepted.error);
}

#[test]
fn accept_signed_progress_reports_the_allocation_right_after_it_succeeds() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_E, MNEMONIC_F);
    let policy = account_policy(&a, &b);
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    let mut device_a = peer(&a);
    let mut device_b = peer(&b);
    prepare_cached_session(&mut module, &mut device_a, &a, &policy);
    prepare_cached_session(&mut module, &mut device_b, &b, &policy);

    let fixture = FundedAttempt::new(&policy);
    let active = fixture.account.active_attempt();
    assert!(active.is_ok, "the active attempt is open: {}", active.error);

    let routes = vec![
        reckless::MusigSignerRoute {
            fingerprint: a.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
        reckless::MusigSignerRoute {
            fingerprint: b.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
    ];
    let signing = reckless::qr_musig_sign_material(
        &a.fingerprint().to_string(),
        &policy,
        &active.psbt_v2_hex,
        routes,
    );
    let message = module.qr_request_sign_musig(signing);
    assert!(
        message.is_ok,
        "the first signature request allocates: {}",
        message.error
    );
    let request::Body::Sign(asked) = wire_request(&message.payload).body else {
        panic!("expected a Signing request");
    };
    assert!(
        !asked.psbt.is_empty(),
        "the request carries the allocated transaction"
    );

    // The device signs with the session the PSBT names; the host verifies the
    // answer and the cache consumes the allocation.
    let decoded = module.qr_decode_response(&answer(&mut device_a, &message.payload));
    assert!(
        decoded.is_ok(),
        "the device's answer decodes: {}",
        decoded.get_error()
    );
    assert_eq!(
        decoded.kind(),
        reckless::QrResponseKind::MusigSignedPsbt,
        "a signing answer of a cached session is recognized as its own kind"
    );
    let accepted = reckless::qr_musig_accept(decoded, &a.fingerprint().to_string(), &policy);
    assert!(
        accepted.is_ok && !accepted.psbt_v2_hex.is_empty(),
        "the signing answer is accepted: {}",
        accepted.error
    );

    let progress = fixture
        .account
        .accept_signed_progress(&accepted.psbt_v2_hex);
    assert!(
        progress.is_ok,
        "the allocation progress is accepted: {}",
        progress.error
    );
    assert!(
        progress.nonces_allocated,
        "the accepted progress reports the allocation"
    );
    assert!(
        fixture.account.active_attempt().nonces_allocated,
        "the attempt reads the allocation back"
    );
    fixture.finish();
}

// ===== A device's own refusal (ws-plaude/silent#135) =====

// Pairs of their own, so these cases' caches never mix with the others'.
const MNEMONIC_G: &str =
    "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge";
const MNEMONIC_H: &str = "gravity machine north sort system female filter attitude volume fold \
     club stay feature office ecology stable narrow fog";
const MNEMONIC_I: &str = "hamster diagram private dutch cause delay private meat slide toddler \
     razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
const MNEMONIC_J: &str = "scheme spot photo card baby mountain device kick cradle pact join borrow";

/// The device's error response to the wire request it was shown.
fn refusal(payload: &[u8], error: response::Error) -> Vec<u8> {
    let request = wire_request(payload);
    encode_response(&bipqr::ll::Response {
        id: request.id,
        body: response::Body::Error(response::ErrorBody {
            message_type: request.body.message_type(),
            error,
            message: "refused by the device".to_string(),
        }),
    })
    .expect("encode the refusal")
}

/// The device's refusal reaches the caller with its code, whichever way it goes: its
/// 0x0D goes to the cache, which drops the session it names, and comes back with the
/// code; any other refusal is the session's own, the request ended with the code.
fn check_refusal(decoded: Box<reckless::QrResponse>, code: u8, fingerprint: &str, policy: &str) {
    if code != 0x0d {
        assert!(!decoded.is_ok(), "the session refuses the answer at once");
        assert_eq!(
            (decoded.error_kind(), decoded.device_error_code()),
            (reckless::QrErrorKind::DeviceRefused, code),
            "the device's refusal keeps its code: {}",
            decoded.get_error()
        );
        return;
    }
    assert!(
        decoded.is_ok(),
        "a device's lost session goes to the cache: {}",
        decoded.get_error()
    );
    let accepted = reckless::qr_musig_accept(decoded, fingerprint, policy);
    assert!(!accepted.is_ok, "a refusal prepares or signs nothing");
    assert_eq!(
        (accepted.device_code, accepted.musig_session),
        (code, false),
        "the device's 0x0D keeps its code, not Reckless's own lost session: {}",
        accepted.error
    );
}

#[test]
fn a_devices_refusal_of_a_nonce_preparation_keeps_its_code() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_G, MNEMONIC_H);
    let policy = account_policy(&a, &b);
    let fingerprint = a.fingerprint().to_string();
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    for (error, code) in [
        (response::Error::MusigSession, 0x0d),
        (response::Error::UserDeclined, 0x01),
    ] {
        let material = reckless::qr_musig_prepare_material(&fingerprint, &policy);
        let message = module.qr_request_prepare_musig(material);
        assert!(message.is_ok, "the prepare request: {}", message.error);
        let decoded = module.qr_decode_response(&refusal(&message.payload, error));
        check_refusal(decoded, code, &fingerprint, &policy);
    }
    // Reckless's own failure, an answer no device sent, keeps no code.
    let material = reckless::qr_musig_prepare_material(&fingerprint, &policy);
    let message = module.qr_request_prepare_musig(material);
    assert!(message.is_ok, "the prepare request: {}", message.error);
    let decoded = module.qr_decode_response(b"not a protocol message");
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(!accepted.is_ok && accepted.device_code == 0);
}

#[test]
fn a_devices_refusal_of_a_cached_signing_request_keeps_its_code() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_I, MNEMONIC_J);
    let policy = account_policy(&a, &b);
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    let mut device_a = peer(&a);
    let mut device_b = peer(&b);
    for (error, code) in [
        (response::Error::MusigSession, 0x0d),
        (response::Error::UserDeclined, 0x01),
    ] {
        prepare_cached_session(&mut module, &mut device_a, &a, &policy);
        prepare_cached_session(&mut module, &mut device_b, &b, &policy);
        let fixture = FundedAttempt::named(&policy, "refusal");
        let active = fixture.account.active_attempt();
        assert!(active.is_ok, "the active attempt is open: {}", active.error);
        let routes = vec![
            reckless::MusigSignerRoute {
                fingerprint: a.fingerprint().to_string(),
                route: KeyRouteKind::Qr,
            },
            reckless::MusigSignerRoute {
                fingerprint: b.fingerprint().to_string(),
                route: KeyRouteKind::Qr,
            },
        ];
        let signing = reckless::qr_musig_sign_material(
            &a.fingerprint().to_string(),
            &policy,
            &active.psbt_v2_hex,
            routes,
        );
        let message = module.qr_request_sign_musig(signing);
        assert!(message.is_ok, "the signature request: {}", message.error);
        // The one-round request of the nonce cache, refused by the device.
        let decoded = module.qr_decode_response(&refusal(&message.payload, error));
        check_refusal(decoded, code, &a.fingerprint().to_string(), &policy);
    }
}

// ===== A spent attempt signs again (ws-plaude/silent#136) =====

const MNEMONIC_K: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon agent";
const MNEMONIC_L: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when";

/// The cached one-round signing request of `psbt` by `signer`, from its device's cache.
fn cached_request(
    module: &mut reckless::KeysModule,
    signer: &HotSigner,
    other: &HotSigner,
    policy: &str,
    psbt: &str,
) -> reckless::QrMessageResult {
    let routes = vec![
        reckless::MusigSignerRoute {
            fingerprint: signer.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
        reckless::MusigSignerRoute {
            fingerprint: other.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
    ];
    let signing =
        reckless::qr_musig_sign_material(&signer.fingerprint().to_string(), policy, psbt, routes);
    module.qr_request_sign_musig(signing)
}

#[test]
fn a_cached_spend_signed_before_signs_again_in_a_fresh_attempt() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_K, MNEMONIC_L);
    let policy = account_policy(&a, &b);
    let fingerprint = a.fingerprint().to_string();
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    let added = module.add_key(&fingerprint, "QR device");
    assert!(added.is_ok, "add the key: {}", added.error);
    let registered = module.register_descriptor(&fingerprint, &policy);
    assert!(
        registered.is_ok,
        "register the wallet: {}",
        registered.error
    );
    let mut device_a = peer(&a);
    let mut device_b = peer(&b);
    // The request takes a session of each signer.
    prepare_cached_session(&mut module, &mut device_a, &a, &policy);
    prepare_cached_session(&mut module, &mut device_b, &b, &policy);
    let fixture = FundedAttempt::named(&policy, "renew");
    let active = fixture.account.active_attempt();
    assert!(active.is_ok, "the active attempt is open: {}", active.error);
    let psbt = active.psbt_v2_hex.clone();

    // The first spend consumes its allocation.
    let message = cached_request(&mut module, &a, &b, &policy, &psbt);
    assert!(message.is_ok, "the first request: {}", message.error);
    let decoded = module.qr_decode_response(&answer(&mut device_a, &message.payload));
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(accepted.is_ok, "the first spend signs: {}", accepted.error);

    // The same transaction again: its spent attempt refuses, as before.
    let again = cached_request(&mut module, &a, &b, &policy, &psbt);
    assert!(!again.is_ok, "the spent attempt itself still refuses");

    // Each device prepares its next session.
    prepare_cached_session(&mut module, &mut device_a, &a, &policy);
    prepare_cached_session(&mut module, &mut device_b, &b, &policy);
    // Renewed for a clean round 1: a fresh attempt, signed from the next cached session.
    let renewed = module.renew_spent_musig_attempt(&fingerprint, &psbt);
    assert!(renewed.is_ok, "renew the attempt: {}", renewed.error);
    assert_ne!(
        renewed.psbt_v2_hex, psbt,
        "the PSBT carries a new attempt id"
    );
    let message = cached_request(&mut module, &a, &b, &policy, &renewed.psbt_v2_hex);
    assert!(message.is_ok, "the renewed request: {}", message.error);
    // Its allocation is active now: asked again, it is kept, not renewed.
    let kept = module.renew_spent_musig_attempt(&fingerprint, &renewed.psbt_v2_hex);
    assert!(
        kept.is_ok && kept.psbt_v2_hex == renewed.psbt_v2_hex,
        "an active attempt is kept"
    );
    let decoded = module.qr_decode_response(&answer(&mut device_a, &message.payload));
    let accepted = reckless::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(
        accepted.is_ok && !accepted.psbt_v2_hex.is_empty(),
        "the renewed attempt signs: {}",
        accepted.error
    );

    // The old attempt stays spent: a request for it is still refused.
    let late = cached_request(&mut module, &a, &b, &policy, &psbt);
    assert!(!late.is_ok, "a request for the spent attempt stays refused");
    fixture.finish();
}

// ===== ws-plaude/silent#138: round 2 after a normal round 1 =====

const MNEMONIC_M: &str =
    "cat swing flag economy stadium alone churn speed unique patch report train";
const MNEMONIC_N: &str =
    "vessel ladder alter error federal sibling chat ability sun glass valve picture";
// The cached case's own pair: the two cases never share a fingerprint's cache.
const MNEMONIC_O: &str =
    "picnic tissue steel giraffe airport asthma island room bicycle notice inflict symptom";
const MNEMONIC_P: &str = "remain cradle actor select derive fly other peasant quiz small zoo siren";

/// The module's QR key for `signer`, its device recorded with the MuSig2 and nonce
/// cache capabilities, holding `policy`.
fn cache_capable_qr_key(module: &mut reckless::KeysModule, signer: &HotSigner, policy: &str) {
    let fingerprint = signer.fingerprint().to_string();
    let added = module.add_key(&fingerprint, "QR device");
    assert!(added.is_ok, "add the key: {}", added.error);
    let route = module.add_route(&fingerprint, KeyRouteKind::Qr);
    assert!(route.is_ok, "add the QR route: {}", route.error);
    let device = module.record_device(reckless::LiveDevice {
        device_id: String::new(),
        fingerprint: fingerprint.clone(),
        kind: "qr".into(),
        brand: String::new(),
        model: "QR device".into(),
        serial: String::new(),
        module: "keys".into(),
        version: "1".into(),
        capabilities: reckless::keys::CAPABILITY_ORDINARY
            | reckless::keys::CAPABILITY_TAPROOT
            | reckless::keys::CAPABILITY_MUSIG
            | reckless::keys::CAPABILITY_MUSIG_CACHE,
    });
    assert!(device.is_ok, "record the device: {}", device.error);
    let registered = module.register_descriptor(&fingerprint, policy);
    assert!(
        registered.is_ok,
        "register the wallet: {}",
        registered.error
    );
}

fn plan_candidate(
    module: &reckless::KeysModule,
    psbt: &str,
    signer: &HotSigner,
) -> reckless::SigningCandidate {
    let plan = module.signing_plan(psbt);
    assert!(plan.is_ok, "the signing plan: {}", plan.error);
    let fingerprint = signer.fingerprint().to_string();
    plan.candidates
        .into_iter()
        .find(|candidate| candidate.fingerprint.eq_ignore_ascii_case(&fingerprint))
        .expect("the key is a candidate")
}

/// One MuSig2 round of `signer` over `psbt` (a v2 hex), as its device answers a normal
/// signing request.
fn hot_round(signer: &HotSigner, policy: &str, psbt: &str) -> String {
    let v2 = bwk::bwk_tx::bwk_psbt::PsbtV2::deserialize(&hex::decode(psbt).expect("psbt hex"))
        .expect("psbt v2");
    let mut real = v2.into_bitcoin_psbt().expect("bitcoin psbt");
    let descriptor = reckless::keys::musig_sessions::descriptor(policy).expect("wallet descriptor");
    signer
        .inner_sign(&mut real, &descriptor)
        .expect("the device's round");
    let signed = bwk::bwk_tx::bwk_psbt::PsbtV2::from_bitcoin_psbt(real).expect("back to v2");
    let merged = reckless::merge_signed_psbt(
        psbt,
        &hex::encode(signed.serialize().expect("serialize the answer")),
    );
    assert!(merged.is_ok, "the round merges: {}", merged.error);
    merged.psbt_v2_hex
}

#[test]
fn a_normal_round_two_on_a_cache_capable_qr_key_takes_the_normal_request() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_M, MNEMONIC_N);
    let policy = account_policy(&a, &b);
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    cache_capable_qr_key(&mut module, &a, &policy);
    let fixture = FundedAttempt::named(&policy, "normal_round_two");
    let active = fixture.account.active_attempt();
    assert!(active.is_ok, "the active attempt is open: {}", active.error);
    let round_one = active.psbt_v2_hex.clone();

    // Nothing prepared: round 1 is a normal request, as on a device without the cache.
    let candidate = plan_candidate(&module, &round_one, &a);
    assert!(candidate.cache_supported, "the device advertises the cache");
    assert!(
        !candidate.cache_route,
        "no prepared session: round 1 takes the normal request"
    );

    // Round 1 by the normal route: each device's public nonces, no cache allocation.
    let nonces = hot_round(&b, &policy, &hot_round(&a, &policy, &round_one));
    let candidate = plan_candidate(&module, &nonces, &a);
    assert!(candidate.nonces_done, "the key gave its nonces");
    assert!(
        candidate.cache_supported,
        "the device still advertises the cache"
    );
    assert!(
        candidate.cache_ready,
        "nothing left to prepare: the condition that sent round 2 to the cache before"
    );
    assert!(
        !candidate.cache_route,
        "round 2 after a normal round 1 takes the normal request, not the cache"
    );
    // The normal request carries the complete nonce transcript, and the device's
    // partial signatures merge.
    let request =
        module.qr_request_sign(&a.fingerprint().to_string(), vec![policy.clone()], &nonces);
    assert!(
        request.is_ok,
        "the normal round 2 request: {}",
        request.error
    );
    let signed = hot_round(&a, &policy, &nonces);
    let candidate = plan_candidate(&module, &signed, &a);
    assert!(
        candidate.signatures_done && !candidate.cache_route,
        "the key's partial signatures are in"
    );
    fixture.finish();
}

#[test]
fn a_cached_spend_on_a_cache_capable_qr_key_still_takes_the_cache_route() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_O, MNEMONIC_P);
    let policy = account_policy(&a, &b);
    let mut module = reckless::new_keys_module(FfiNetwork::Regtest);
    cache_capable_qr_key(&mut module, &a, &policy);
    let mut device_a = peer(&a);
    let mut device_b = peer(&b);
    prepare_cached_session(&mut module, &mut device_a, &a, &policy);
    prepare_cached_session(&mut module, &mut device_b, &b, &policy);
    let fixture = FundedAttempt::named(&policy, "cached_route");
    let active = fixture.account.active_attempt();
    assert!(active.is_ok, "the active attempt is open: {}", active.error);
    let psbt = active.psbt_v2_hex.clone();

    let candidate = plan_candidate(&module, &psbt, &a);
    eprintln!(
        "DEBUG route={:?} can_sign={} unusable={:?} supported={} ready={} nonces_done={}",
        candidate.route,
        candidate.can_sign,
        candidate.unusable,
        candidate.cache_supported,
        candidate.cache_ready,
        candidate.nonces_done
    );
    assert!(
        candidate.cache_route,
        "a prepared session covers the transaction: the cache route"
    );
    // The request allocates this attempt's session: the transaction stays on the cache
    // route until its answer.
    let message = cached_request(&mut module, &a, &b, &policy, &psbt);
    assert!(message.is_ok, "the cached request: {}", message.error);
    let candidate = plan_candidate(&module, &psbt, &a);
    assert!(
        candidate.cache_route,
        "the attempt's allocation keeps it on the cache route"
    );
    let decoded = module.qr_decode_response(&answer(&mut device_a, &message.payload));
    let accepted = reckless::qr_musig_accept(decoded, &a.fingerprint().to_string(), &policy);
    assert!(
        accepted.is_ok && !accepted.psbt_v2_hex.is_empty(),
        "the cached spend signs: {}",
        accepted.error
    );
    fixture.finish();
}
