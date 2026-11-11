//! The nonce cache MuSig QR exchange through the module: the material step persists
//! the record, the request is issued, bwk's QR MuSig peer answers it, and the decoded
//! answer lands in the cache as a prepared session. These are the exact module
//! functions the GUI engine's worker and slots call, in the same order.

use std::str::FromStr;
use std::sync::OnceLock;

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
use bwk_qr_protocol::{decode, encode_response, request, response, Message};
use silent::{
    Config, KeyRouteKind, MusigAccount, Network as FfiNetwork, Output, TransactionTemplate,
};

// ===== Datadir =====

static DATADIR: OnceLock<temp_dir::TempDir> = OnceLock::new();

fn datadir() -> &'static std::path::Path {
    DATADIR
        .get_or_init(|| {
            let tmp = temp_dir::TempDir::new().expect("create temp dir");
            silent::set_datadir(tmp.path().to_path_buf());
            silent::state_crypt::unlock_for_tests();
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

fn wire_request(payload: &[u8]) -> bwk_qr_protocol::Request {
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
    let mut module = silent::new_keys_module(FfiNetwork::Regtest);

    // The worker step: the record is persisted, the material handed back.
    let material = silent::qr_musig_prepare_material(&fingerprint, &policy);
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
        (8, 0, 0),
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
        silent::QrResponseKind::MusigPrepared,
        "a prepared answer is recognized as its own kind"
    );
    let accepted = silent::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(accepted.is_ok, "the answer is accepted: {}", accepted.error);
    assert_eq!(
        silent::musig_session_count(&fingerprint, &policy, KeyRouteKind::Qr),
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
    let mut module = silent::new_keys_module(FfiNetwork::Regtest);

    let material = silent::qr_musig_prepare_material(&fingerprint, &policy);
    let message = module.qr_request_prepare_musig(material);
    assert!(message.is_ok, "the prepare request is issued");

    let honest = answer(&mut peer(&a), &message.payload);
    let Message::Response(mut stranger) = decode(&honest).expect("decode the answer") else {
        panic!("expected a response");
    };
    let response::Body::NoncesPrepared(prepared) = &mut stranger.body else {
        panic!("expected prepared nonces");
    };
    prepared.session_id = [0xab; 4];
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
    let accepted = silent::qr_musig_accept(decoded, &fingerprint, &policy);
    assert!(
        accepted.is_ok,
        "the honest answer is accepted: {}",
        accepted.error
    );
    assert_eq!(
        silent::musig_session_count(&fingerprint, &policy, KeyRouteKind::Qr),
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
        assert!(
            silent::validate_musig_descriptor(policy.to_string()).is_ok,
            "the account policy is accepted"
        );
        let name = format!("qr_cache_attempt_{}", std::process::id());
        let config = silent::new_config(
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
        let mut account = silent::new_musig_account(name);
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
        silent::delete_config(name);
    }
}

/// Runs the nonce preparation exchange for one device, in the order the GUI engine's
/// worker and slots call the module functions.
fn prepare_cached_session(
    module: &mut silent::KeysModule,
    device: &mut Peer,
    signer: &HotSigner,
    policy: &str,
) {
    let fingerprint = signer.fingerprint().to_string();
    let material = silent::qr_musig_prepare_material(&fingerprint, policy);
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
    let accepted = silent::qr_musig_accept(decoded, &fingerprint, policy);
    assert!(accepted.is_ok, "the answer is accepted: {}", accepted.error);
}

#[test]
fn accept_signed_progress_reports_the_allocation_right_after_it_succeeds() {
    let dir = datadir();
    assert!(dir.exists(), "the datadir fixture is set");
    let (a, b) = signers_on(MNEMONIC_E, MNEMONIC_F);
    let policy = account_policy(&a, &b);
    let mut module = silent::new_keys_module(FfiNetwork::Regtest);
    let mut device_a = peer(&a);
    let mut device_b = peer(&b);
    prepare_cached_session(&mut module, &mut device_a, &a, &policy);
    prepare_cached_session(&mut module, &mut device_b, &b, &policy);

    let fixture = FundedAttempt::new(&policy);
    let active = fixture.account.active_attempt();
    assert!(active.is_ok, "the active attempt is open: {}", active.error);

    let routes = vec![
        silent::MusigSignerRoute {
            fingerprint: a.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
        silent::MusigSignerRoute {
            fingerprint: b.fingerprint().to_string(),
            route: KeyRouteKind::Qr,
        },
    ];
    let signing = silent::qr_musig_sign_material(
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
        silent::QrResponseKind::MusigSignedPsbt,
        "a signing answer of a cached session is recognized as its own kind"
    );
    let accepted = silent::qr_musig_accept(decoded, &a.fingerprint().to_string(), &policy);
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
