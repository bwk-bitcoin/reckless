//! The five signing-flow QR requests, their trip through BBQR frames, and every
//! response refusal `QrSession` enforces.
//!
//! None of these cases touch a key record, so no datadir override is needed here.

mod common;

use std::str::FromStr;

use bipqr::{
    backend::{Active, Backend},
    ll::{
        decode, encode_request, encode_response,
        request::{self, KeyKind, KeyRequest},
        response,
        types::{ExtendedKey, Fingerprint as ProtocolFingerprint},
        Message, MessageType, Request, RequestId, Response,
    },
};
use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath},
    hashes::Hash,
    transaction,
};
use bwk_sp::{
    bwk_sign::{
        bwk_descriptor::{
            descriptor::{tr_path, wpkh, wpkh_path, DescriptorDerivator},
            wallet::to_wallet,
        },
        hot_signer::HotSigner,
    },
    bwk_tx::bwk_psbt::{
        sp::{set_sp_input_ecdh_share, set_sp_input_tweak, sp_input_ecdh_share, sp_input_tweak},
        Input as PsbtInput, Output as PsbtOutput, PsbtV2,
    },
};
use reckless::keys::{
    psbt::merge_signatures_bytes,
    qr::{QrResponse, QrSession},
    Error,
};

// ===== PSBT fixtures =====

fn one_input_psbt() -> PsbtV2 {
    PsbtV2 {
        tx_version: transaction::Version::TWO,
        fallback_lock_time: Some(LockTime::ZERO),
        tx_modifiable: None,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: vec![PsbtInput {
            previous_output: bitcoin::OutPoint::new(Hash::all_zeros(), 0),
            sequence: bitcoin::Sequence::MAX,
            required_time_lock_time: None,
            required_height_lock_time: None,
            psbt: bitcoin::psbt::Input::default(),
        }],
        outputs: vec![PsbtOutput {
            amount: bitcoin::Amount::from_sat(1_000),
            script_pubkey: Some(bitcoin::ScriptBuf::new()),
            psbt: bitcoin::psbt::Output::default(),
        }],
    }
}

fn sign_psbt_bytes() -> Vec<u8> {
    one_input_psbt().serialize().expect("serialize psbt")
}

/// Comfortably larger than the 1024-byte default BBQR part size, so the request
/// splits into more than one frame.
const BIG_UNKNOWN_LEN: usize = 4_000;
const BIG_UNKNOWN_KEYTYPE: u8 = 0xf0;

fn big_sign_psbt_bytes() -> Vec<u8> {
    let mut psbt = one_input_psbt();
    psbt.unknown.insert(
        bitcoin::psbt::raw::Key {
            type_value: BIG_UNKNOWN_KEYTYPE,
            key: Vec::new(),
        },
        vec![0u8; BIG_UNKNOWN_LEN],
    );
    psbt.serialize().expect("serialize big psbt")
}

/// A `Keys` response body from a stable firmware, carrying `keys` for `fingerprint`.
fn keys_body(keys: Vec<ExtendedKey>, fingerprint: [u8; 4]) -> response::Body {
    response::Body::Keys(response::Keys {
        keys,
        fingerprint: ProtocolFingerprint(fingerprint),
        vendor: "vendor".to_string(),
        model: "model".to_string(),
        version: response::FirmwareVersion {
            major: 1,
            minor: 0,
            patch: 0,
            flag: response::ReleaseFlag::Stable,
        },
        capabilities: response::Capabilities(0),
    })
}

fn sp_descriptor_without_origin() -> String {
    let scan_xprv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x71; 64]).expect("seed");
    let spend_xprv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x72; 64]).expect("seed");
    format!("sp({scan_xprv}/0h,{spend_xprv}/0h)")
}

// ===== Signable PSBT fixtures, for the request-binding and signature-merge cases =====

const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon about";
const RECEIVE_INDEX: u32 = 0;

fn blank_input(previous_output: bitcoin::OutPoint) -> PsbtInput {
    PsbtInput {
        previous_output,
        sequence: bitcoin::Sequence::MAX,
        required_time_lock_time: None,
        required_height_lock_time: None,
        psbt: bitcoin::psbt::Input::default(),
    }
}

fn blank_output(script_pubkey: Option<bitcoin::ScriptBuf>) -> PsbtOutput {
    PsbtOutput {
        amount: bitcoin::Amount::from_sat(1_000),
        script_pubkey,
        psbt: bitcoin::psbt::Output::default(),
    }
}

fn public_key(
    secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    byte: u8,
) -> bitcoin::secp256k1::PublicKey {
    bitcoin::secp256k1::PublicKey::from_secret_key(
        secp,
        &bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).expect("valid key"),
    )
}

/// The account-level wpkh() descriptor derived from the test mnemonic, and the origin
/// path it was built at.
fn wpkh_descriptor(network: bitcoin::Network) -> (String, DerivationPath) {
    let account = ChildNumber::from_hardened_idx(0).expect("valid account index");
    let path = wpkh_path(network, account).expect("valid wpkh path");
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    let xpub = signer.xpub(&path);
    (wpkh(xpub).to_string(), path)
}

/// One input spending `descriptor_string` at receive index 0 from the test mnemonic,
/// carrying the bip32_derivation and witness_utxo a hot signer needs to sign it. No
/// silent payment fields.
fn signable_input(
    network: bitcoin::Network,
    descriptor_string: &str,
    path: &DerivationPath,
) -> PsbtInput {
    let descriptor =
        to_wallet(
            bwk_sp::bwk_sign::miniscript::Descriptor::<
                bwk_sp::bwk_sign::miniscript::DescriptorPublicKey,
            >::from_str(descriptor_string)
            .expect("valid wpkh descriptor"),
        );
    let derivator = descriptor
        .spk_derivator(network)
        .expect("valid spk derivator");
    let spk = derivator.receive_spk_at(RECEIVE_INDEX);

    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    let full_path = path
        .child(ChildNumber::from_normal_idx(0).expect("receive branch"))
        .child(ChildNumber::from_normal_idx(RECEIVE_INDEX).expect("receive index"));
    let pubkey = signer.public_key_at(&full_path);

    let mut input = blank_input(bitcoin::OutPoint::new(Hash::all_zeros(), 0));
    input
        .psbt
        .bip32_derivation
        .insert(pubkey, (signer.fingerprint(), full_path));
    input.psbt.witness_utxo = Some(bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(100_000),
        script_pubkey: spk,
    });
    input
}

/// A v2 PSBT with one signable, non-SP input. The output script is already derived,
/// so nothing here is pending.
fn non_sp_signable_psbt(
    network: bitcoin::Network,
    descriptor_string: &str,
    path: &DerivationPath,
) -> PsbtV2 {
    let input = signable_input(network, descriptor_string, path);
    PsbtV2 {
        tx_version: transaction::Version::TWO,
        fallback_lock_time: Some(LockTime::ZERO),
        tx_modifiable: None,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: vec![input],
        outputs: vec![blank_output(Some(bitcoin::ScriptBuf::new()))],
    }
}

/// The same signable psbt, with an SP input tweak and ECDH share added, so a build
/// of the sign request carries it to the device unconverted (`has_sp_artifacts`).
fn sp_signable_psbt(
    network: bitcoin::Network,
    descriptor_string: &str,
    path: &DerivationPath,
) -> PsbtV2 {
    let mut psbt = non_sp_signable_psbt(network, descriptor_string, path);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    set_sp_input_tweak(&mut psbt.inputs[0].psbt, [0x22; 32]);
    set_sp_input_ecdh_share(
        &mut psbt.inputs[0].psbt,
        public_key(&secp, 0x33),
        public_key(&secp, 0x34),
    );
    psbt
}

/// Only `decode_response` (protocol decode + validation) is exercised here, so an
/// error is always the crate's own `keys::error::Error`, which is `Display`-able
/// but not `Debug`-checked against `Result::expect_err`. Matching by hand keeps
/// every negative case asserting the same way.
fn expect_refused(session: &mut QrSession, bytes: &[u8]) -> String {
    match session.decode_response(bytes) {
        Ok(_) => panic!("expected the response to be refused"),
        Err(e) => e.to_string(),
    }
}

// ===== Case 9: every request round trips through the protocol codec =====

#[test]
fn test_five_requests_round_trip() {
    let mut session = QrSession::new();

    let xpubs = session
        .get_xpubs(vec![DerivationPath::from_str("m/84'/1'/0'").expect("path")])
        .expect("get_xpubs request");
    let register = session
        .register_descriptor("wpkh(desc)")
        .expect("register_descriptor request");
    let verify = session
        .verify_address(
            "wpkh(desc)",
            DerivationPath::from_str("m/0/0").expect("path"),
            "address".to_string(),
        )
        .expect("verify_address request");
    let sign = session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let sp_account = session
        .get_sp_account(bitcoin::Network::Regtest)
        .expect("get_sp_account request");

    let ids = [
        xpubs.id(),
        register.id(),
        verify.id(),
        sign.id(),
        sp_account.id(),
    ];
    for id in &ids {
        assert_ne!(
            id.0,
            [0, 0],
            "the reserved zero id must never be issued, got {ids:?}"
        );
    }
    let mut sorted_ids: Vec<[u8; 2]> = ids.iter().map(|id| id.0).collect();
    sorted_ids.sort_unstable();
    sorted_ids.dedup();
    assert_eq!(
        sorted_ids.len(),
        ids.len(),
        "expected 5 distinct request ids, got {ids:?}"
    );

    for (request, expected_type) in [
        (&xpubs, MessageType::GetKeys),
        (&register, MessageType::RegisterDescriptor),
        (&verify, MessageType::AddressVerification),
        (&sign, MessageType::Signing),
        (&sp_account, MessageType::GetKeys),
    ] {
        match decode(request.message()).expect("decode request message") {
            Message::Request(decoded) => {
                assert_eq!(
                    decoded.id,
                    request.id(),
                    "decoded id must match the request's own id"
                );
                assert_eq!(
                    decoded.body.message_type(),
                    expected_type,
                    "decoded body must match the kind that was asked for"
                );
            }
            Message::Response(_) => panic!("expected a request, decoded a response"),
        }
    }
}

// ===== Case 10: a multi-part sign request trips through BBQR frames =====

#[test]
fn test_sign_request_round_trips_through_bbqr_frames() {
    let mut session = QrSession::new();
    let request = session
        .sign(&["wpkh(desc)".to_string()], &big_sign_psbt_bytes())
        .expect("sign request");

    let frames = reckless::bbqr::frames(request.message(), 200).expect("frame the request");
    assert!(
        frames.len() > 1,
        "expected the oversized psbt to split into multiple frames, got {}",
        frames.len()
    );
    let mut scanner = reckless::bbqr::Scanner::new().expect("create scanner");
    let mut payloads = Vec::new();
    for frame in &frames {
        let rgb: Vec<u8> = frame.data.iter().flat_map(|&luma| [luma; 3]).collect();
        let outcome = scanner.scan(&rgb, frame.width, frame.height);
        payloads.extend(outcome.payloads);
    }
    assert_eq!(
        payloads,
        vec![request.message().to_vec()],
        "the joined payload must be the request message"
    );
}

// ===== Case 11: a response answering a different request id is refused =====

#[test]
fn test_request_id_mismatch_is_refused() {
    let mut session = QrSession::new();
    let request = session
        .get_sp_account(bitcoin::Network::Regtest)
        .expect("get_sp_account request");
    let outstanding_hex = format!("{:02x}{:02x}", request.id().0[0], request.id().0[1]);

    let wrong_id = RequestId([0xff, 0xff]);
    let response = Response {
        id: wrong_id,
        body: keys_body(Vec::new(), [0u8; 4]),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = expect_refused(&mut session, &encoded);
    assert!(
        error.contains(&outstanding_hex) && error.contains("ffff"),
        "expected the error to carry both ids, got {error}"
    );
}

// ===== Case 12: fewer xpubs than paths requested is refused =====

#[test]
fn test_bad_xpub_count_is_refused() {
    let mut session = QrSession::new();
    session
        .get_xpubs(vec![
            DerivationPath::from_str("m/84'/1'/0'").expect("path"),
            DerivationPath::from_str("m/84'/1'/1'").expect("path"),
        ])
        .expect("get_xpubs request");

    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: keys_body(vec![ExtendedKey([0u8; 78])], [0u8; 4]),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = expect_refused(&mut session, &encoded);
    assert!(
        error.contains('2') && error.contains('1'),
        "expected the error to name both counts (2 requested, 1 returned), got {error}"
    );
}

// ===== Case 13: a signed payload that is not a parsable PSBT is refused =====

#[test]
fn test_garbage_signed_psbt_is_refused() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");

    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Signed(response::Signed::Psbt(vec![1, 2, 3])),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = expect_refused(&mut session, &encoded);
    assert!(
        error.to_lowercase().contains("psbt"),
        "expected the error to mention the psbt, got {error}"
    );
}

// ===== Case 14: bare signatures are refused, only a full PSBT is accepted =====

#[test]
fn test_bare_signatures_are_refused() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");

    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Signed(response::Signed::Signatures(Vec::new())),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = expect_refused(&mut session, &encoded);
    assert!(
        error.contains("full") && error.to_lowercase().contains("psbt"),
        "expected the error to say only a full psbt is accepted, got {error}"
    );
}

// ===== Case 17: a v0 signed answer merges into the original v2 request =====

#[test]
fn test_v0_signed_answer_merges_into_the_original_v2() {
    let network = bitcoin::Network::Bitcoin;
    let (descriptor_string, path) = wpkh_descriptor(network);
    let original = non_sp_signable_psbt(network, &descriptor_string, &path);
    let original_bytes = original.serialize().expect("serialize original");

    let mut session = QrSession::new();
    session
        .sign(&[descriptor_string.clone()], &original_bytes)
        .expect("sign request");

    let mut v0 = original.clone().into_bitcoin_psbt().expect("into v0");
    let descriptor =
        to_wallet(
            bwk_sp::bwk_sign::miniscript::Descriptor::<
                bwk_sp::bwk_sign::miniscript::DescriptorPublicKey,
            >::from_str(&descriptor_string)
            .expect("valid wpkh descriptor"),
        );
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    signer
        .inner_sign(&mut v0, &descriptor)
        .expect("sign succeeds");
    assert!(
        !v0.inputs[0].partial_sigs.is_empty(),
        "expected a partial signature on the signed v0 psbt"
    );
    let signed_v0_bytes = v0.serialize();

    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Signed(response::Signed::Psbt(signed_v0_bytes.clone())),
    };
    let encoded = encode_response(&response).expect("encode response");

    let decoded = session
        .decode_response(&encoded)
        .expect("response accepted");
    let merged_bytes = match decoded {
        QrResponse::SignedPsbt(bytes) => bytes,
        _ => panic!("expected a SignedPsbt response"),
    };

    let merged_psbt = PsbtV2::deserialize(&merged_bytes).expect("merged psbt parses as v2");
    assert!(
        !merged_psbt.inputs[0].psbt.partial_sigs.is_empty(),
        "expected the merged psbt to carry the device's signature"
    );

    let expected = merge_signatures_bytes(&original_bytes, &signed_v0_bytes)
        .expect("compute the expected merge independently");
    assert_eq!(
        merged_bytes, expected,
        "expected the decoded bytes to equal the original plus the device's signatures"
    );
}

// ===== Case 18: a v2 signed answer keeps the original's SP fields intact =====

#[test]
fn test_v2_signed_answer_keeps_sp_fields_intact() {
    let network = bitcoin::Network::Bitcoin;
    let (descriptor_string, path) = wpkh_descriptor(network);
    let original = sp_signable_psbt(network, &descriptor_string, &path);
    let original_bytes = original.serialize().expect("serialize original");

    let mut session = QrSession::new();
    session
        .sign(&[descriptor_string.clone()], &original_bytes)
        .expect("sign request");

    let mut v0 = original.clone().into_bitcoin_psbt().expect("into v0");
    let descriptor =
        to_wallet(
            bwk_sp::bwk_sign::miniscript::Descriptor::<
                bwk_sp::bwk_sign::miniscript::DescriptorPublicKey,
            >::from_str(&descriptor_string)
            .expect("valid wpkh descriptor"),
        );
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    signer
        .inner_sign(&mut v0, &descriptor)
        .expect("sign succeeds");

    // The device answers with the full v2 payload it received, signatures added.
    let mut signed_v2 = original.clone();
    signed_v2.inputs[0].psbt.partial_sigs = v0.inputs[0].partial_sigs.clone();
    let signed_v2_bytes = signed_v2.serialize().expect("serialize signed v2");

    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Signed(response::Signed::Psbt(signed_v2_bytes)),
    };
    let encoded = encode_response(&response).expect("encode response");

    let decoded = session
        .decode_response(&encoded)
        .expect("response accepted");
    let merged_bytes = match decoded {
        QrResponse::SignedPsbt(bytes) => bytes,
        _ => panic!("expected a SignedPsbt response"),
    };

    let merged_psbt = PsbtV2::deserialize(&merged_bytes).expect("merged psbt parses as v2");
    assert!(
        !merged_psbt.inputs[0].psbt.partial_sigs.is_empty(),
        "expected the merged psbt to carry the device's signature"
    );

    let secp = bitcoin::secp256k1::Secp256k1::new();
    assert_eq!(
        sp_input_tweak(&merged_psbt.inputs[0].psbt).expect("valid tweak field"),
        Some([0x22; 32]),
        "expected the sp input tweak to survive the merge"
    );
    assert_eq!(
        sp_input_ecdh_share(&merged_psbt.inputs[0].psbt, public_key(&secp, 0x33))
            .expect("valid ecdh share field"),
        Some(public_key(&secp, 0x34)),
        "expected the sp ecdh share to survive the merge"
    );
}

// ===== Case 19: a signed answer for another transaction is refused, the request stays =====

#[test]
fn test_signed_answer_for_a_different_transaction_is_refused_and_keeps_the_outstanding_request() {
    let network = bitcoin::Network::Bitcoin;
    let (descriptor_string, path) = wpkh_descriptor(network);
    let original = non_sp_signable_psbt(network, &descriptor_string, &path);
    let original_bytes = original.serialize().expect("serialize original");

    let mut session = QrSession::new();
    session
        .sign(&[descriptor_string], &original_bytes)
        .expect("sign request");
    let outstanding_id = session.outstanding_id().expect("outstanding request");

    let other_input = blank_input(bitcoin::OutPoint::new(Hash::from_byte_array([0x44; 32]), 0));
    let other_psbt = PsbtV2 {
        tx_version: transaction::Version::TWO,
        fallback_lock_time: Some(LockTime::ZERO),
        tx_modifiable: None,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: vec![other_input],
        outputs: vec![blank_output(Some(bitcoin::ScriptBuf::new()))],
    };
    let other_v0_bytes = other_psbt.into_bitcoin_psbt().expect("into v0").serialize();

    let response = Response {
        id: outstanding_id,
        body: response::Body::Signed(response::Signed::Psbt(other_v0_bytes)),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = match session.decode_response(&encoded) {
        Ok(_) => panic!("a signed psbt for another transaction must be refused"),
        Err(e) => e,
    };
    assert!(
        matches!(error, Error::SignedPsbtMismatch { .. }),
        "expected SignedPsbtMismatch, got {error}"
    );
    assert_eq!(
        session.outstanding_id(),
        Some(outstanding_id),
        "expected the outstanding request to survive a refused response"
    );
}

// ===== Case 20: a signed answer identical to the request signs nothing =====

#[test]
fn test_signed_answer_identical_to_the_request_is_refused_as_nothing_signed() {
    let network = bitcoin::Network::Bitcoin;
    let (descriptor_string, path) = wpkh_descriptor(network);
    let original = non_sp_signable_psbt(network, &descriptor_string, &path);
    let original_bytes = original.serialize().expect("serialize original");

    let mut session = QrSession::new();
    session
        .sign(&[descriptor_string], &original_bytes)
        .expect("sign request");
    let outstanding_id = session.outstanding_id().expect("outstanding request");

    let unsigned_v0_bytes = original
        .clone()
        .into_bitcoin_psbt()
        .expect("into v0")
        .serialize();

    let response = Response {
        id: outstanding_id,
        body: response::Body::Signed(response::Signed::Psbt(unsigned_v0_bytes)),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = match session.decode_response(&encoded) {
        Ok(_) => panic!("an unsigned answer must be refused"),
        Err(e) => e,
    };
    assert!(
        matches!(error, Error::NothingSigned),
        "expected NothingSigned, got {error}"
    );
}

// ===== Case 21: an accepted xpubs response carries what it says about the device =====

#[test]
fn test_xpubs_response_carries_the_device() {
    let network = bitcoin::Network::Bitcoin;
    let path = DerivationPath::from_str("m/84'/0'/0'").expect("path");
    let xpub = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC)
        .expect("valid signer")
        .xpub(&path)
        .xkey;

    let mut session = QrSession::new();
    session
        .get_xpubs(vec![path.clone()])
        .expect("get_xpubs request");
    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Keys(response::Keys {
            keys: vec![Active::to_ll_xpub(&xpub)],
            fingerprint: ProtocolFingerprint([0xde, 0xad, 0xbe, 0xef]),
            vendor: "vendor".to_string(),
            model: "model".to_string(),
            version: response::FirmwareVersion {
                major: 1,
                minor: 2,
                patch: 3,
                flag: response::ReleaseFlag::Stable,
            },
            capabilities: response::Capabilities(0x0000_000b),
        }),
    };
    let encoded = encode_response(&response).expect("encode response");

    let Ok(QrResponse::Xpubs {
        fingerprint,
        xpubs,
        vendor,
        model,
        version,
        capabilities,
    }) = session.decode_response(&encoded)
    else {
        panic!("expected an accepted xpubs response");
    };
    assert_eq!(
        fingerprint.to_string(),
        "deadbeef",
        "unexpected fingerprint"
    );
    assert_eq!(xpubs, vec![(path, xpub)], "unexpected xpubs");
    assert_eq!(vendor, "vendor", "unexpected vendor");
    assert_eq!(model, "model", "unexpected model");
    assert_eq!(version, "1.2.3", "unexpected version");
    assert_eq!(capabilities, 0x0000_000b, "unexpected capabilities");
}

// ===== Case 22: the four account xpubs of an added key come back in request order =====

#[test]
fn test_four_path_xpubs_response_keeps_the_request_order() {
    let network = bitcoin::Network::Bitcoin;
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    let paths: Vec<DerivationPath> = [
        "m/84'/0'/0'",
        "m/86'/0'/0'",
        "m/48'/0'/0'/2'",
        "m/87'/0'/0'",
    ]
    .iter()
    .map(|path| DerivationPath::from_str(path).expect("path"))
    .collect();
    let expected: Vec<_> = paths
        .iter()
        .map(|path| (path.clone(), signer.xpub(path).xkey))
        .collect();

    let mut session = QrSession::new();
    session.get_xpubs(paths).expect("get_xpubs request");
    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: keys_body(
            expected
                .iter()
                .map(|(_, xpub)| Active::to_ll_xpub(xpub))
                .collect(),
            [0xde, 0xad, 0xbe, 0xef],
        ),
    };
    let encoded = encode_response(&response).expect("encode response");

    let Ok(QrResponse::Xpubs { xpubs, .. }) = session.decode_response(&encoded) else {
        panic!("expected an accepted xpubs response");
    };
    assert_eq!(
        xpubs, expected,
        "expected the four xpubs paired with their paths in request order"
    );
}

// ===== Silent payment address verification =====

const SP_ADDRESS: &str = "tsp1qqexample";

/// An sp() descriptor of a signet account, its scan secret in clear.
fn sp_descriptor_with_origin() -> (String, String) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let scan_xprv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, &[0x71; 64]).expect("seed");
    let spend_xprv =
        bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Signet, &[0x72; 64]).expect("seed");
    let fp = scan_xprv.fingerprint(&secp);
    (
        format!("sp([{fp}/352h/1h/0h]{scan_xprv}/0h,{spend_xprv}/0h)"),
        fp.to_string(),
    )
}

fn sp_verify_request(session: &mut QrSession) -> (RequestId, request::VerifyAddress) {
    let (descriptor, _) = sp_descriptor_with_origin();
    let request = session
        .verify_address(
            &descriptor,
            DerivationPath::master(),
            SP_ADDRESS.to_string(),
        )
        .expect("sp verify_address request");
    match decode(request.message()).expect("decodes") {
        Message::Request(Request {
            id,
            body: request::Body::VerifyAddress(body),
        }) => (id, body),
        other => panic!("not a verify address request: {other:?}"),
    }
}

#[test]
fn test_sp_verify_request_carries_the_account_keys_not_the_descriptor() {
    let (descriptor, fp) = sp_descriptor_with_origin();
    let (_, body) = sp_verify_request(&mut QrSession::new());
    assert_eq!(
        body.descriptor,
        Some(request::DescriptorBody::SpKeys(request::SpKeys {
            fingerprint: Active::to_ll_fingerprint(
                &bitcoin::bip32::Fingerprint::from_str(&fp).unwrap()
            ),
            spend_path: Active::to_ll_path(&DerivationPath::from_str("m/352'/1'/0'/0'/0").unwrap()),
            scan: request::Scan::Path(Active::to_ll_path(
                &DerivationPath::from_str("m/352'/1'/0'/1'/0").unwrap()
            )),
        }))
    );
    // No label: the account's own address.
    assert!(body.derivation_path.0.is_empty());
    assert_eq!(body.address.as_deref(), Some(SP_ADDRESS));
    assert!(body.proof.is_none());
    // The scan secret never reaches the code shown on screen.
    let scan_xprv = descriptor
        .split([']', '/'])
        .find(|part| part.starts_with("tprv"))
        .expect("the fixture holds a tprv");
    let request = QrSession::new()
        .verify_address(
            &descriptor,
            DerivationPath::master(),
            SP_ADDRESS.to_string(),
        )
        .expect("request");
    assert!(!String::from_utf8_lossy(request.message()).contains(scan_xprv));
}

#[test]
fn test_sp_verify_request_needs_the_descriptor_origin() {
    let mut session = QrSession::new();
    let result = session.verify_address(
        &sp_descriptor_without_origin(),
        DerivationPath::master(),
        SP_ADDRESS.to_string(),
    );
    assert!(matches!(result, Err(Error::SpDescriptorNoOrigin)));
}

#[test]
fn test_sp_verify_answer_is_compared_with_the_address() {
    // A device answers a silent payment address as BIP-321's `sp=` parameter
    // (ws-plaude/silent#122); the URI path is only a fallback address, never compared.
    for (answered, matched) in [
        (format!("bitcoin:?sp={SP_ADDRESS}"), true),
        ("bitcoin:?sp=tsp1qqother".to_string(), false),
        (format!("bitcoin:{SP_ADDRESS}"), false),
    ] {
        let mut session = QrSession::new();
        let (id, _) = sp_verify_request(&mut session);
        let answer = encode_response(&Response {
            id,
            body: response::Body::AddressUri(response::AddressUri {
                uri: answered.clone(),
            }),
        })
        .expect("encodes");
        match session.decode_response(&answer) {
            Ok(QrResponse::AddressVerified(verified)) => {
                assert_eq!(verified, matched, "answered {answered}")
            }
            Ok(_) => panic!("not an address verification"),
            Err(e) => panic!("refused: {e}"),
        }
    }
}

// ===== Silent payment account =====

const TEST_FINGERPRINT: [u8; 4] = [0x73, 0xc5, 0xda, 0x0a];

/// The networks an sp account is asked on, with their reckless `Network` and the coin
/// type of their paths.
const SP_ACCOUNT_NETWORKS: [(bitcoin::Network, reckless::Network, u32); 2] = [
    (bitcoin::Network::Regtest, reckless::Network::Regtest, 1),
    (bitcoin::Network::Bitcoin, reckless::Network::Bitcoin, 0),
];

fn path(path: &str) -> DerivationPath {
    DerivationPath::from_str(path).expect("valid path")
}

/// The spend, scan, taproot and segwit paths of the test account, in request order.
fn sp_account_paths(coin: u32) -> [DerivationPath; 4] {
    [
        path(&format!("m/352'/{coin}'/0'/0'/0")),
        path(&format!("m/352'/{coin}'/0'/1'/0")),
        path(&format!("m/86'/{coin}'/0'")),
        path(&format!("m/84'/{coin}'/0'")),
    ]
}

/// The keys a signer on the test mnemonic answers an sp account request with: the
/// spend key public, the scan key private, the taproot and segwit xpubs.
fn sp_account_keys(network: bitcoin::Network, coin: u32) -> Vec<ExtendedKey> {
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    let [spend, scan, taproot, segwit] = sp_account_paths(coin);
    vec![
        Active::to_ll_xpub(&signer.xpub(&spend).xkey),
        Active::to_ll_xpriv(&signer.xpriv(&scan).xkey),
        Active::to_ll_xpub(&signer.xpub(&taproot).xkey),
        Active::to_ll_xpub(&signer.xpub(&segwit).xkey),
    ]
}

/// Issues an sp account request and answers it with `keys` from the test key.
fn answer_sp_account(
    network: bitcoin::Network,
    keys: Vec<ExtendedKey>,
) -> Result<QrResponse, Error> {
    let mut session = QrSession::new();
    session
        .get_sp_account(network)
        .expect("get_sp_account request");
    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: keys_body(keys, TEST_FINGERPRINT),
    };
    let encoded = encode_response(&response).expect("encode response");
    session.decode_response(&encoded)
}

#[test]
fn test_sp_account_request_asks_the_four_keys() {
    for (network, _, coin) in SP_ACCOUNT_NETWORKS {
        let request = QrSession::new()
            .get_sp_account(network)
            .expect("get_sp_account request");
        let keys = match decode(request.message()).expect("decodes") {
            Message::Request(Request {
                body: request::Body::GetKeys(body),
                ..
            }) => body.keys,
            other => panic!("not a get keys request: {other:?}"),
        };
        let expected: Vec<KeyRequest> = [
            (format!("m/352'/{coin}'/0'/0'/0"), KeyKind::Public),
            (format!("m/352'/{coin}'/0'/1'/0"), KeyKind::Private),
            (format!("m/86'/{coin}'/0'"), KeyKind::Public),
            (format!("m/84'/{coin}'/0'"), KeyKind::Public),
        ]
        .into_iter()
        .map(|(key_path, kind)| KeyRequest {
            derivation_path: Active::to_ll_path(&path(&key_path)),
            kind,
        })
        .collect();
        assert_eq!(
            keys, expected,
            "unexpected key requests on {network}: spend public, scan private, then the \
             taproot and segwit xpubs"
        );
    }
}

#[test]
fn test_sp_account_response_builds_the_watch_only_descriptor() {
    for (network, reckless_network, coin) in SP_ACCOUNT_NETWORKS {
        let answer = answer_sp_account(network, sp_account_keys(network, coin));
        let Ok(QrResponse::SpAccount {
            descriptor,
            fingerprint,
            xpubs,
        }) = answer
        else {
            panic!("expected an accepted sp account response on {network}");
        };
        assert_eq!(
            descriptor,
            common::descriptor_from_mnemonic(TEST_MNEMONIC, reckless_network),
            "expected the hot key's watch-only sp() descriptor on {network}"
        );
        assert_eq!(
            fingerprint.to_string(),
            "73c5da0a",
            "unexpected fingerprint on {network}"
        );
        let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
        let account = ChildNumber::from_hardened_idx(0).expect("valid account index");
        let taproot = tr_path(network, account).expect("valid tr path");
        let segwit = wpkh_path(network, account).expect("valid wpkh path");
        assert_eq!(
            xpubs,
            vec![
                (taproot.clone(), signer.xpub(&taproot).xkey),
                (segwit.clone(), signer.xpub(&segwit).xkey),
            ],
            "expected the taproot and segwit xpubs with their paths on {network}"
        );
    }
}

#[test]
fn test_sp_account_key_of_the_wrong_kind_is_refused() {
    let network = bitcoin::Network::Regtest;
    let signer = HotSigner::new_from_mnemonics(network, TEST_MNEMONIC).expect("valid signer");
    let [spend, scan, _, _] = sp_account_paths(1);

    // The scan key as an xpub.
    let mut keys = sp_account_keys(network, 1);
    keys[1] = Active::to_ll_xpub(&signer.xpub(&scan).xkey);
    let error = answer_sp_account(network, keys).err();
    assert!(
        matches!(
            &error,
            Some(Error::KeyKindMismatch { path, requested: KeyKind::Private }) if *path == scan
        ),
        "expected a private key mismatch at the scan path, got {error:?}"
    );

    // The spend key as an xpriv.
    let mut keys = sp_account_keys(network, 1);
    keys[0] = Active::to_ll_xpriv(&signer.xpriv(&spend).xkey);
    let error = answer_sp_account(network, keys).err();
    assert!(
        matches!(
            &error,
            Some(Error::KeyKindMismatch { path, requested: KeyKind::Public }) if *path == spend
        ),
        "expected a public key mismatch at the spend path, got {error:?}"
    );
}

#[test]
fn test_sp_account_key_count_mismatch_is_refused() {
    let network = bitcoin::Network::Regtest;
    let mut keys = sp_account_keys(network, 1);
    keys.pop();
    let error = answer_sp_account(network, keys).err();
    assert!(
        matches!(
            error,
            Some(Error::XpubCountMismatch {
                requested: 4,
                returned: 3
            })
        ),
        "expected 4 keys requested and 3 returned, got {error:?}"
    );
}

#[test]
fn test_sp_account_private_key_export_refusal_surfaces() {
    let mut session = QrSession::new();
    session
        .get_sp_account(bitcoin::Network::Regtest)
        .expect("get_sp_account request");
    let response = Response {
        id: session.outstanding_id().expect("outstanding request"),
        body: response::Body::Error(response::ErrorBody {
            message_type: MessageType::GetKeys,
            error: response::Error::from(0x0c),
            message: "scan branch only".to_string(),
        }),
    };
    let encoded = encode_response(&response).expect("encode response");

    let error = session.decode_response(&encoded).err();
    assert!(
        matches!(
            &error,
            Some(Error::SignerRefused {
                message_type: MessageType::GetKeys,
                code: response::Error::PrivateKeyExportRefused,
                message,
            }) if message == "scan branch only"
        ),
        "expected the signer's private key export refusal, got {error:?}"
    );
}

// ===== Signer refusals of a signing request =====
//
// The nonce cache MuSig exchanges are built and checked by bwk's QR MuSig host on
// cache material: they are covered with the cache, in `keys_qr_cache.rs` and the
// QR provider's unit tests.

fn respond(session: &QrSession, body: response::Body) -> Vec<u8> {
    encode_response(&Response {
        id: session.outstanding_id().expect("outstanding request"),
        body,
    })
    .expect("encode response")
}

fn refusal(error: response::Error, message: &str) -> response::Body {
    response::Body::Error(response::ErrorBody {
        message_type: MessageType::Signing,
        error,
        message: message.to_string(),
    })
}

#[test]
fn test_an_alias_registered_with_another_descriptor_is_its_own_refusal() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = respond(
        &session,
        refusal(response::Error::AlreadyRegistered, "alias taken"),
    );
    let error = session.decode_response(&encoded).err();
    assert!(
        matches!(
            &error,
            Some(Error::AlreadyRegistered {
                message_type: MessageType::Signing,
                message,
            }) if message == "alias taken"
        ),
        "expected the already registered refusal, got {error:?}"
    );
    assert!(
        session.outstanding_id().is_some(),
        "a refused answer leaves the request outstanding: the scan goes on"
    );
}

// ws-plaude/silent#106: 0x0F, 0x10 and the unreadable request reply are their own errors.
#[test]
fn test_an_unsupported_operation_is_its_own_refusal() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = respond(
        &session,
        refusal(response::Error::UnsupportedOperation, "no signing"),
    );
    let error = session.decode_response(&encoded).err();
    assert!(
        matches!(
            &error,
            Some(Error::SignerUnsupported {
                message_type: MessageType::Signing,
                message,
            }) if message == "no signing"
        ),
        "expected the unsupported operation refusal, got {error:?}"
    );
    assert!(error.unwrap().to_string().contains("does not support"));
    assert!(session.outstanding_id().is_some());
}

#[test]
fn test_a_network_mismatch_is_its_own_refusal() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = respond(
        &session,
        refusal(response::Error::NetworkMismatch, "mainnet only"),
    );
    let error = session.decode_response(&encoded).err();
    assert!(
        matches!(&error, Some(Error::SignerNetworkMismatch { message }) if message == "mainnet only"),
        "expected the network mismatch refusal, got {error:?}"
    );
    assert!(error.unwrap().to_string().contains("another network"));
    assert!(session.outstanding_id().is_some());
}

#[test]
fn test_the_unreadable_request_reply_is_not_a_request_id_mismatch() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = encode_response(&Response::unreadable_request("bad header".to_string()))
        .expect("encode response");
    let error = session.decode_response(&encoded).err();
    assert!(
        matches!(&error, Some(Error::SignerUnreadableRequest { message }) if message == "bad header"),
        "expected the unreadable request error, got {error:?}"
    );
    assert!(error
        .unwrap()
        .to_string()
        .contains("the device could not read the request"));
    assert!(
        session.outstanding_id().is_some(),
        "the request stays outstanding for a new scan"
    );
}

#[test]
fn test_a_lost_session_on_an_ordinary_signing_request_is_a_musig_session_error() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = respond(
        &session,
        refusal(response::Error::MusigSession, "no session"),
    );
    assert!(
        matches!(session.decode_response(&encoded), Err(Error::MusigSession)),
        "a refusal for a MuSig2 session is reported as such"
    );
}

#[test]
fn test_a_nonce_preparation_answer_to_a_signing_request_is_refused() {
    let mut session = QrSession::new();
    session
        .sign(&["wpkh(desc)".to_string()], &sign_psbt_bytes())
        .expect("sign request");
    let encoded = respond(
        &session,
        response::Body::NoncesPrepared(response::NoncesPrepared {
            session: Some(response::Session {
                session_id: [1; 4],
                session_ref: [2; 4],
            }),
            nonces: vec![[2; 66]],
        }),
    );
    assert!(
        matches!(
            session.decode_response(&encoded),
            Err(Error::ResponseKindMismatch {
                expected: MessageType::Signing,
                got: MessageType::NoncePreparation,
            })
        ),
        "a nonce preparation answers no signing request"
    );
}

// ws-plaude/silent#114: a registration answer carries whether the device stored the
// registration and, when it did not, the proof a later request carries.
#[test]
fn the_registration_answer_keeps_whether_it_was_stored_and_its_proof() {
    let descriptor = "wpkh([73c5da0a/84h/1h/0h]tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/<0;1>/*)";
    for (stored, proof) in [
        (Some(false), Some(vec![7u8; 32])),
        (Some(true), None),
        (None, None),
    ] {
        let mut session = QrSession::new();
        session
            .register_descriptor(descriptor)
            .expect("register_descriptor request");
        let encoded = respond(
            &session,
            response::Body::Registration(response::Registration {
                descriptor_alias: "alias".into(),
                registered: true,
                stored,
                proof: proof.clone(),
            }),
        );
        let answer = session
            .decode_response(&encoded)
            .expect("registration answer");
        let QrResponse::Registration {
            alias,
            registered,
            stored: got_stored,
            proof: got_proof,
        } = answer
        else {
            panic!("expected a registration answer, got {answer:?}");
        };
        assert_eq!((alias.as_str(), registered), ("alias", true));
        assert_eq!((got_stored, got_proof), (stored, proof));
    }
}

// ws-plaude/silent#115: a registration check is the registration request with the
// wallet's alias and no descriptor body, and its answer says whether the device holds it.
#[test]
fn a_registration_check_carries_no_descriptor_and_reads_the_answer() {
    for registered in [true, false] {
        let mut session = QrSession::new();
        let check = session
            .check_registration("wpkh(desc)")
            .expect("check_registration request");
        let Message::Request(decoded) = decode(check.message()).expect("decode request") else {
            panic!("expected a request");
        };
        let request::Body::RegisterDescriptor(body) = decoded.body else {
            panic!("expected the registration request, got {:?}", decoded.body);
        };
        assert!(
            body.descriptor.is_none(),
            "a check carries no descriptor body"
        );
        assert!(
            !body.descriptor_alias.is_empty(),
            "a check names the wallet's alias"
        );
        let encoded = respond(
            &session,
            response::Body::Registration(response::Registration {
                descriptor_alias: body.descriptor_alias,
                registered,
                stored: None,
                proof: None,
            }),
        );
        let answer = session.decode_response(&encoded).expect("check answer");
        assert!(
            matches!(answer, QrResponse::Registration { registered: got, .. } if got == registered),
            "expected registered {registered}, got {answer:?}"
        );
    }
}

// ws-plaude/silent#117: a request to a device carries what its registration needs: the
// alias alone when it kept the wallet, the body and its proof when it gave one, the body
// alone when no answer is recorded.
#[test]
fn requests_carry_the_body_and_proof_or_the_alias_as_the_registration_says() {
    use reckless::keys::qr::QrRegistration;
    let proof = vec![9u8; 40];
    for (registration, body, carried_proof) in [
        (QrRegistration::Unknown, true, None),
        (QrRegistration::Stored, false, None),
        (
            QrRegistration::Proof(proof.clone()),
            true,
            Some(proof.clone()),
        ),
    ] {
        let mut session = QrSession::new();
        let sign = session
            .sign_registered(&["wpkh(desc)".to_string()], &sign_psbt_bytes(), &|_| {
                registration.clone()
            })
            .expect("sign request");
        let Message::Request(decoded) = decode(sign.message()).expect("decode sign") else {
            panic!("expected a request");
        };
        let request::Body::Sign(signing) = decoded.body else {
            panic!("expected a signing request");
        };
        let named = &signing.descriptors[0];
        assert!(!named.alias.is_empty(), "the wallet is named by its alias");
        assert_eq!(named.descriptor.is_some(), body, "{registration:?}: body");
        assert_eq!(named.proof, carried_proof, "{registration:?}: proof");

        let mut session = QrSession::new();
        let verify = session
            .verify_address_registered(
                "wpkh(desc)",
                DerivationPath::from_str("m/0/0").expect("path"),
                "address".to_string(),
                &registration,
            )
            .expect("verify request");
        let Message::Request(decoded) = decode(verify.message()).expect("decode verify") else {
            panic!("expected a request");
        };
        let request::Body::VerifyAddress(verification) = decoded.body else {
            panic!("expected an address verification");
        };
        assert_eq!(
            verification.descriptor.is_some(),
            body,
            "{registration:?}: body"
        );
        assert_eq!(verification.proof, carried_proof, "{registration:?}: proof");
    }
}

// ws-plaude/silent#130: the Unregister Descriptor request names the wallet by its alias
// alone, encoded as bipqr's vectors are; the device's ok answer is read as the wallet
// forgotten, and its refusals keep their codes.
#[test]
fn an_unregistration_names_the_alias_and_reads_the_answer_as_the_vectors_are() {
    // bipqr test_vectors/unregister_descriptor.json, alias "main", REQUEST_ID 1.
    let request_vector = hex::decode("42495058585801070001046d61696e").expect("hex");
    let answer_vector = hex::decode("42495058585801870001046d61696e").expect("hex");
    assert_eq!(
        encode_request(&Request {
            id: RequestId([0x00, 0x01]),
            body: request::Body::UnregisterDescriptor(request::UnregisterDescriptor {
                descriptor_alias: "main".to_string(),
            }),
        })
        .expect("encode"),
        request_vector,
        "the codec encodes the request as the vector"
    );

    let mut session = QrSession::new();
    let unregister = session
        .unregister_descriptor("wpkh(desc)")
        .expect("unregister request");
    let Message::Request(decoded) = decode(unregister.message()).expect("decode request") else {
        panic!("expected a request");
    };
    assert_eq!(decoded.id, unregister.id());
    let request::Body::UnregisterDescriptor(body) = decoded.body else {
        panic!("expected the unregister request, got {:?}", decoded.body);
    };
    assert!(
        !body.descriptor_alias.is_empty() && body.descriptor_alias.len() <= 32,
        "the request names the wallet's alias, {:?}",
        body.descriptor_alias
    );
    // The session's message is the vector's with its own alias and REQUEST_ID.
    assert_eq!(
        unregister.message(),
        encode_request(&Request {
            id: unregister.id(),
            body: request::Body::UnregisterDescriptor(request::UnregisterDescriptor {
                descriptor_alias: body.descriptor_alias.clone(),
            }),
        })
        .expect("encode"),
    );

    // The vector's answer, under this request's id, is the wallet forgotten.
    let mut answer = answer_vector.clone();
    answer[8..10].copy_from_slice(&unregister.id().0);
    let read = session.decode_response(&answer).expect("the ok answer");
    assert!(
        matches!(&read, QrResponse::Unregistered { alias } if alias == "main"),
        "expected the wallet forgotten, got {read:?}"
    );

    // A refusal keeps its code: 0x04 (not held), 0x01 (declined), 0x0F (keeps none).
    for error in [
        response::Error::UnknownDescriptorAlias,
        response::Error::UserDeclined,
        response::Error::UnsupportedOperation,
    ] {
        let mut session = QrSession::new();
        session
            .unregister_descriptor("wpkh(desc)")
            .expect("unregister request");
        let encoded = respond(
            &session,
            response::Body::Error(response::ErrorBody {
                message_type: MessageType::UnregisterDescriptor,
                error,
                message: "refused".to_string(),
            }),
        );
        let refused = session.decode_response(&encoded);
        let kept = match &refused {
            Err(Error::SignerRefused { code, .. }) => *code == error,
            // 0x0F has its own variant, which the bridge reports as 0x0F.
            Err(Error::SignerUnsupported { message_type, .. }) => {
                error == response::Error::UnsupportedOperation
                    && *message_type == MessageType::UnregisterDescriptor
            }
            _ => false,
        };
        assert!(
            kept,
            "expected the device's refusal {error:?}, got {refused:?}"
        );
    }
}
