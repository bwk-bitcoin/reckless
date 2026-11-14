//! ws-plaude/silent#123: plain wallets paying a silent payment address, through the
//! keys module's real plan and hot signers. The sending keys hold no sp() descriptor:
//! their input keys give the BIP-375 ECDH shares. With one key, it gives the shares,
//! derives the output and signs in one answer. With two keys, each first gives its own
//! inputs' shares, the output is derived once both are in, and each key then signs.
//! Every case ends with valid signatures and the output script the recipient finds
//! with its scan key.
//!
//! ws-plaude/silent#132: the same over QR codes. A fake device holding each seed answers
//! the session's real bipqr Signing requests in real bipqr bytes, the PSBT it got with,
//! while the output is pending, its own inputs' ECDH shares and DLEQ proofs, nothing
//! signed; once derived, its signatures. An invalid proof and a device's refusal stop it cleanly.
//!
//! The file shares one datadir, so each case uses its own network to keep the test
//! mnemonics' keys apart.

use std::str::FromStr;

use bipqr::ll::{encode_response, response, MessageType, Response};
use bitcoin::{
    bip32::{ChildNumber, DerivationPath},
    ecdsa,
    key::TweakedPublicKey,
    secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid,
};
use bwk_sp::{
    account::bip375,
    bwk_sign::{
        bwk_descriptor::{
            descriptor::{wpkh, wpkh_path, DescriptorDerivator},
            wallet::to_wallet,
        },
        hot_signer::HotSigner,
    },
    bwk_tx::bwk_psbt::{
        sp::{set_sp_v0_output, sp_input_ecdh_shares},
        Input as PsbtInput, Output as PsbtOutput, PsbtV2,
    },
    core::utils::common::{calculate_P_n, calculate_t_n},
};
use bwk_sp::{
    bwk_tx::bwk_psbt::sp::{set_sp_input_dleq, sp_input_dleq},
    signer::write_input_ecdh_share,
};
use reckless::keys::{
    qr::{QrResponse, QrSession},
    Error,
};
use reckless::{KeyRouteKind, KeyUnusableReason, Network as FfiNetwork};

static DATADIR: std::sync::OnceLock<temp_dir::TempDir> = std::sync::OnceLock::new();

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

const FIRST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon about";
const SECOND_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
const PASSWORD: &str = "password";
const INPUT_SATS: u64 = 100_000;
const PAID_SATS: u64 = 150_000;

/// The recipient: its scan and spend keys, the scan one secret only to check the
/// derived output as the recipient would.
fn recipient() -> (SecretKey, PublicKey, PublicKey) {
    let secp = Secp256k1::new();
    let scan = SecretKey::from_slice(&[0x11; 32]).expect("valid scan key");
    let spend = SecretKey::from_slice(&[0x22; 32]).expect("valid spend key");
    (
        scan,
        PublicKey::from_secret_key(&secp, &scan),
        PublicKey::from_secret_key(&secp, &spend),
    )
}

struct Key {
    signer: HotSigner,
    descriptor: String,
    fingerprint: String,
    /// The key of its receive address 0, which the input spends.
    pubkey: PublicKey,
    path: DerivationPath,
    spk: ScriptBuf,
}

fn key(network: Network, mnemonic: &str) -> Key {
    let account = ChildNumber::from_hardened_idx(0).expect("valid account index");
    let path = wpkh_path(network, account).expect("valid wpkh path");
    let signer = HotSigner::new_from_mnemonics(network, mnemonic).expect("valid signer");
    let descriptor = wpkh(signer.xpub(&path)).to_string();
    let wallet =
        to_wallet(
            bwk_sp::bwk_sign::miniscript::Descriptor::<
                bwk_sp::bwk_sign::miniscript::DescriptorPublicKey,
            >::from_str(&descriptor)
            .expect("valid wpkh descriptor"),
        );
    let spk = wallet
        .spk_derivator(network)
        .expect("valid spk derivator")
        .receive_spk_at(0);
    let full_path = path
        .child(ChildNumber::from_normal_idx(0).expect("receive branch"))
        .child(ChildNumber::from_normal_idx(0).expect("receive index"));
    let pubkey = signer.public_key_at(&full_path);
    Key {
        fingerprint: signer.fingerprint().to_string(),
        signer,
        descriptor,
        pubkey,
        path: full_path,
        spk,
    }
}

fn input(key: &Key, vout: u32) -> PsbtInput {
    let mut input = PsbtInput {
        previous_output: OutPoint::new(Txid::from_str(&"ab".repeat(32)).expect("txid"), vout),
        sequence: Sequence::MAX,
        required_time_lock_time: None,
        required_height_lock_time: None,
        psbt: bitcoin::psbt::Input::default(),
    };
    input
        .psbt
        .bip32_derivation
        .insert(key.pubkey, (key.signer.fingerprint(), key.path.clone()));
    input.psbt.witness_utxo = Some(TxOut {
        value: Amount::from_sat(INPUT_SATS),
        script_pubkey: key.spk.clone(),
    });
    input
}

/// A PSBT spending one input of each key in `keys` to the recipient's silent payment
/// address, its output script still to derive.
fn payment(keys: &[&Key]) -> PsbtV2 {
    let (_, scan, spend) = recipient();
    let mut output = PsbtOutput {
        amount: Amount::from_sat(PAID_SATS),
        script_pubkey: None,
        psbt: bitcoin::psbt::Output::default(),
    };
    set_sp_v0_output(&mut output.psbt, scan, spend, None);
    PsbtV2 {
        tx_version: bitcoin::transaction::Version::TWO,
        fallback_lock_time: Some(bitcoin::absolute::LockTime::ZERO),
        tx_modifiable: None,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
        inputs: keys
            .iter()
            .enumerate()
            .map(|(vout, key)| input(key, u32::try_from(vout).expect("vout")))
            .collect(),
        outputs: vec![output],
    }
}

/// The output script the recipient finds with its scan key (BIP-352): the inputs'
/// keys summed and tweaked by the input hash, times the scan key, k = 0.
fn expected_script(psbt: &PsbtV2, keys: &[&Key]) -> ScriptBuf {
    let secp = Secp256k1::new();
    let (scan, _, spend) = recipient();
    let sum = PublicKey::combine_keys(&keys.iter().map(|key| &key.pubkey).collect::<Vec<_>>())
        .expect("input keys sum");
    let input_hash = bip375::input_hash(psbt).expect("input hash");
    let ecdh = sum
        .mul_tweak(&secp, &input_hash)
        .and_then(|point| point.mul_tweak(&secp, &Scalar::from(scan)))
        .expect("shared secret");
    let t_0 = calculate_t_n(&ecdh, 0).expect("t_0");
    let output = calculate_P_n(&spend, Scalar::from(t_0)).expect("P_0");
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
        output.x_only_public_key().0,
    ))
}

/// Every input's signature verifies against the transaction as it now is.
fn check_signatures(psbt: &PsbtV2) {
    let secp = Secp256k1::verification_only();
    let tx: Transaction = psbt.unsigned_tx().expect("the transaction is complete");
    let mut cache = SighashCache::new(&tx);
    for (index, input) in psbt.inputs.iter().enumerate() {
        let (pubkey, signature): (&bitcoin::PublicKey, &ecdsa::Signature) = input
            .psbt
            .partial_sigs
            .iter()
            .next()
            .expect("every input is signed");
        let utxo = input.psbt.witness_utxo.as_ref().expect("witness utxo");
        let sighash = cache
            .p2wpkh_signature_hash(
                index,
                &utxo.script_pubkey,
                utxo.value,
                EcdsaSighashType::All,
            )
            .expect("sighash");
        secp.verify_ecdsa(&Message::from(sighash), &signature.signature, &pubkey.inner)
            .expect("the signature verifies");
    }
}

fn module(network: FfiNetwork, keys: &[&Key]) -> Box<reckless::KeysModule> {
    let mut module = reckless::new_keys_module(network);
    assert!(module.is_ok(), "module opens: {}", module.get_error());
    for (key, mnemonic) in keys.iter().zip([FIRST_MNEMONIC, SECOND_MNEMONIC]) {
        let sealed = reckless::hot_seal(mnemonic, PASSWORD, network);
        assert!(sealed.is_ok(), "seal: {}", sealed.get_error());
        let committed = module.commit_hot_key(&sealed, "hot key");
        assert!(committed.is_ok, "commit: {}", committed.error);
        let registered = module.register_descriptor(&key.fingerprint, &key.descriptor);
        assert!(registered.is_ok, "register: {}", registered.error);
    }
    module
}

fn sign(module: &reckless::KeysModule, key: &Key, psbt: &PsbtV2) -> PsbtV2 {
    let material = module.hot_material(&key.fingerprint);
    assert!(material.is_ok(), "hot material: {}", material.get_error());
    let hex = hex::encode(psbt.serialize().expect("serialize"));
    let signed = reckless::hot_sign(&material, PASSWORD, &hex, Vec::new());
    assert!(signed.is_ok, "hot sign: {}", signed.error);
    PsbtV2::deserialize(&hex::decode(&signed.psbt_v2_hex).expect("hex")).expect("psbt v2")
}

fn plan(module: &reckless::KeysModule, psbt: &PsbtV2) -> reckless::SigningPlan {
    let plan = module.signing_plan(&hex::encode(psbt.serialize().expect("serialize")));
    assert!(plan.is_ok, "plan: {}", plan.error);
    plan
}

fn candidate<'a>(plan: &'a reckless::SigningPlan, key: &Key) -> &'a reckless::SigningCandidate {
    plan.candidates
        .iter()
        .find(|candidate| candidate.fingerprint == key.fingerprint)
        .expect("the key is a candidate")
}

#[test]
fn a_wpkh_wallet_pays_a_silent_payment_address_with_one_key() {
    let _ = datadir();
    let key = key(Network::Regtest, FIRST_MNEMONIC);
    let module = module(FfiNetwork::Regtest, &[&key]);
    let unsigned = payment(&[&key]);
    let first = plan(&module, &unsigned);
    assert!(
        candidate(&first, &key).can_sign && candidate(&first, &key).must_sign_first,
        "the wallet's key, with no sp() descriptor, signs: {:?}",
        first.candidates
    );
    let signed = sign(&module, &key, &unsigned);
    assert_eq!(
        signed.outputs[0].script_pubkey,
        Some(expected_script(&signed, &[&key])),
        "the derived output is the one the recipient finds"
    );
    check_signatures(&signed);
}

#[test]
fn two_keys_give_their_shares_then_sign() {
    let _ = datadir();
    let first = key(Network::Signet, FIRST_MNEMONIC);
    let second = key(Network::Signet, SECOND_MNEMONIC);
    let module = module(FfiNetwork::Signet, &[&first, &second]);
    let unsigned = payment(&[&first, &second]);

    // Both keys owe their shares: either may go first.
    let start = plan(&module, &unsigned);
    for key in [&first, &second] {
        assert!(
            candidate(&start, key).can_sign && candidate(&start, key).must_sign_first,
            "each key owing its shares signs first: {:?}",
            start.candidates
        );
    }

    // The first key's answer is its input's shares alone: the output waits.
    let shared = sign(&module, &first, &unsigned);
    assert!(
        shared.outputs[0].script_pubkey.is_none(),
        "the output waits on the second key"
    );
    assert!(
        !sp_input_ecdh_shares(&shared.inputs[0].psbt)
            .expect("shares")
            .is_empty()
            && sp_input_ecdh_shares(&shared.inputs[1].psbt)
                .expect("shares")
                .is_empty(),
        "the first key gave its own input's share only"
    );
    assert!(
        shared
            .inputs
            .iter()
            .all(|input| input.psbt.partial_sigs.is_empty()),
        "nothing is signed before the output exists"
    );
    let waiting = plan(&module, &shared);
    assert!(
        !candidate(&waiting, &first).can_sign
            && candidate(&waiting, &first).unusable == KeyUnusableReason::SpOutputsPending,
        "the first key waits for the output: {:?}",
        waiting.candidates
    );
    assert!(
        candidate(&waiting, &second).can_sign && candidate(&waiting, &second).must_sign_first,
        "the second key gives its share next: {:?}",
        waiting.candidates
    );

    // The second key's share completes them: it derives the output and signs.
    let derived = sign(&module, &second, &shared);
    assert_eq!(
        derived.outputs[0].script_pubkey,
        Some(expected_script(&derived, &[&first, &second])),
        "the output is derived from both keys' shares, as the recipient finds it"
    );
    assert!(
        !derived.inputs[1].psbt.partial_sigs.is_empty()
            && derived.inputs[0].psbt.partial_sigs.is_empty(),
        "the second key signed its own input"
    );

    // With the output derived, the first key signs as any key.
    let ready = plan(&module, &derived);
    assert!(
        candidate(&ready, &first).can_sign && !candidate(&ready, &first).must_sign_first,
        "the first key signs now: {:?}",
        ready.candidates
    );
    let signed = sign(&module, &first, &derived);
    assert_eq!(
        signed.outputs, derived.outputs,
        "signing keeps the derived output"
    );
    check_signatures(&signed);
}

// ===== Over QR codes (ws-plaude/silent#132) =====

/// How a fake device answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Device {
    Honest,
    /// Its share's DLEQ proof has a flipped byte.
    BadProof,
    /// The user declines on it (bipqr 0x01).
    Declines,
}

/// What a device holding `key`'s seed answers to `psbt`, as Reckless's request asks
/// for a PSBT without MuSig2 inputs: the PSBT v2 it got, with, while the output is
/// pending, the ECDH share and DLEQ proof of each of its inputs; once derived, their
/// signatures.
fn device_answer(key: &Key, psbt: &PsbtV2, device: Device) -> Vec<u8> {
    let secp = Secp256k1::new();
    let owned: Vec<usize> = psbt
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| input.psbt.bip32_derivation.contains_key(&key.pubkey))
        .map(|(index, _)| index)
        .collect();
    let mut answer = psbt.clone();
    if psbt
        .outputs
        .iter()
        .any(|output| output.script_pubkey.is_none())
    {
        let scan_keys = bip375::scan_keys(psbt).expect("scan keys");
        let secret = key.signer.private_key_at(&key.path);
        for index in owned {
            let input = &mut answer.inputs[index].psbt;
            write_input_ecdh_share(input, &scan_keys, secret, [0x07; 32], &secp)
                .expect("share and proof");
            if device == Device::BadProof {
                for scan_key in &scan_keys {
                    let mut proof = sp_input_dleq(input, *scan_key)
                        .expect("proof")
                        .expect("proof");
                    proof[10] ^= 0x01;
                    set_sp_input_dleq(input, *scan_key, proof);
                }
            }
        }
    } else {
        let mut v0 = psbt.clone().into_bitcoin_psbt().expect("v0");
        let wallet = to_wallet(
            bwk_sp::bwk_sign::miniscript::Descriptor::<
                bwk_sp::bwk_sign::miniscript::DescriptorPublicKey,
            >::from_str(&key.descriptor)
            .expect("valid wpkh descriptor"),
        );
        key.signer
            .inner_sign(&mut v0, &wallet)
            .expect("the device signs");
        for index in owned {
            answer.inputs[index].psbt.partial_sigs = v0.inputs[index].partial_sigs.clone();
        }
    }
    answer.serialize().expect("serialize the answer")
}

/// One Signing exchange with the device holding `key`: the session's request for
/// `psbt`, the device's answer in real bipqr bytes, decoded and checked by the session.
fn qr_round(key: &Key, psbt: &PsbtV2, device: Device) -> Result<PsbtV2, Error> {
    let mut session = QrSession::new();
    session
        .sign(
            &[key.descriptor.clone()],
            &psbt.serialize().expect("serialize"),
        )
        .expect("the signing request");
    let body = if device == Device::Declines {
        response::Body::Error(response::ErrorBody {
            message_type: MessageType::Signing,
            error: response::Error::UserDeclined,
            message: "declined on the device".to_string(),
        })
    } else {
        response::Body::Signed(response::Signed::Psbt(device_answer(key, psbt, device)))
    };
    let answer = encode_response(&Response {
        id: session.outstanding_id().expect("outstanding request"),
        body,
    })
    .expect("encode the answer");
    match session.decode_response(&answer)? {
        QrResponse::SignedPsbt(bytes) => Ok(PsbtV2::deserialize(&bytes).expect("psbt v2")),
        other => panic!("not a signed answer: {other:?}"),
    }
}

fn qr_module(
    network: FfiNetwork,
    qr: &[&Key],
    hot: Option<(&Key, &str)>,
) -> Box<reckless::KeysModule> {
    let mut module = reckless::new_keys_module(network);
    assert!(module.is_ok(), "module opens: {}", module.get_error());
    for key in qr {
        let added = module.add_key(&key.fingerprint, "QR device");
        assert!(added.is_ok, "add key: {}", added.error);
        let route = module.add_route(&key.fingerprint, KeyRouteKind::Qr);
        assert!(route.is_ok, "add route: {}", route.error);
        let registered = module.register_descriptor(&key.fingerprint, &key.descriptor);
        assert!(registered.is_ok, "register: {}", registered.error);
    }
    if let Some((key, mnemonic)) = hot {
        let sealed = reckless::hot_seal(mnemonic, PASSWORD, network);
        assert!(sealed.is_ok(), "seal: {}", sealed.get_error());
        let committed = module.commit_hot_key(&sealed, "hot key");
        assert!(committed.is_ok, "commit: {}", committed.error);
        let registered = module.register_descriptor(&key.fingerprint, &key.descriptor);
        assert!(registered.is_ok, "register: {}", registered.error);
    }
    module
}

#[test]
fn two_qr_keys_give_their_shares_then_sign() {
    let _ = datadir();
    let first = key(Network::Testnet, FIRST_MNEMONIC);
    let second = key(Network::Testnet, SECOND_MNEMONIC);
    let module = qr_module(FfiNetwork::Testnet, &[&first, &second], None);
    let unsigned = payment(&[&first, &second]);
    let start = plan(&module, &unsigned);
    for key in [&first, &second] {
        assert!(
            candidate(&start, key).can_sign && candidate(&start, key).must_sign_first,
            "each QR key owing its shares signs first: {:?}",
            start.candidates
        );
    }

    // Round 1: each device answers its input's share and proof, nothing signed.
    let shared = qr_round(&first, &unsigned, Device::Honest).expect("the first device's shares");
    assert!(
        shared.outputs[0].script_pubkey.is_none(),
        "the output waits on the second key"
    );
    assert!(shared
        .inputs
        .iter()
        .all(|input| input.psbt.partial_sigs.is_empty()));
    let waiting = plan(&module, &shared);
    assert!(
        candidate(&waiting, &first).unusable == KeyUnusableReason::SpOutputsPending
            && candidate(&waiting, &second).can_sign,
        "the second device is next: {:?}",
        waiting.candidates
    );
    let derived = qr_round(&second, &shared, Device::Honest).expect("the second device's shares");
    assert_eq!(
        derived.outputs[0].script_pubkey,
        Some(expected_script(&derived, &[&first, &second])),
        "Reckless derives the output from both devices' shares, as the recipient finds it"
    );
    assert!(derived
        .inputs
        .iter()
        .all(|input| input.psbt.partial_sigs.is_empty()));

    // Round 2: each device signs its input.
    let ready = plan(&module, &derived);
    for key in [&first, &second] {
        assert!(
            candidate(&ready, key).can_sign && !candidate(&ready, key).must_sign_first,
            "both devices sign now: {:?}",
            ready.candidates
        );
    }
    let half = qr_round(&first, &derived, Device::Honest).expect("the first device signs");
    let signed = qr_round(&second, &half, Device::Honest).expect("the second device signs");
    assert_eq!(
        signed.outputs, derived.outputs,
        "signing keeps the derived output"
    );
    check_signatures(&signed);
}

#[test]
fn a_qr_key_and_a_hot_key_give_their_shares_then_sign() {
    let _ = datadir();
    let device = key(Network::Bitcoin, FIRST_MNEMONIC);
    let hot = key(Network::Bitcoin, SECOND_MNEMONIC);
    let module = qr_module(
        FfiNetwork::Bitcoin,
        &[&device],
        Some((&hot, SECOND_MNEMONIC)),
    );
    let unsigned = payment(&[&device, &hot]);

    let shared = qr_round(&device, &unsigned, Device::Honest).expect("the device's shares");
    assert!(shared.outputs[0].script_pubkey.is_none());
    // The hot key gives its share, derives the output and signs its input.
    let derived = sign(&module, &hot, &shared);
    assert_eq!(
        derived.outputs[0].script_pubkey,
        Some(expected_script(&derived, &[&device, &hot])),
        "the output is derived from the device's and the hot key's shares"
    );
    let signed = qr_round(&device, &derived, Device::Honest).expect("the device signs");
    check_signatures(&signed);
}

#[test]
fn a_bad_proof_or_a_refusal_stops_the_payment() {
    let _ = datadir();
    let first = key(Network::Regtest, FIRST_MNEMONIC);
    let second = key(Network::Regtest, SECOND_MNEMONIC);
    let unsigned = payment(&[&first, &second]);

    // A share whose DLEQ proof does not verify is refused at once, before any output.
    let refused = qr_round(&first, &unsigned, Device::BadProof);
    assert!(
        matches!(&refused, Err(Error::SpSignedInvalid(message)) if message.contains("DLEQ")),
        "an invalid proof is refused: {refused:?}"
    );
    // The same against the second device's round, the first's share being in.
    let shared = qr_round(&first, &unsigned, Device::Honest).expect("the first device's shares");
    let refused = qr_round(&second, &shared, Device::BadProof);
    assert!(
        matches!(&refused, Err(Error::SpSignedInvalid(_))),
        "an invalid proof completing the shares is refused too: {refused:?}"
    );

    // A device that declines answers its refusal; the PSBT is left as it was.
    let declined = qr_round(&second, &shared, Device::Declines);
    assert!(
        matches!(
            &declined,
            Err(Error::SignerRefused {
                code: response::Error::UserDeclined,
                ..
            })
        ),
        "a declined request is the device's refusal, 0x01, and gives no PSBT: {declined:?}"
    );
    let resumed = qr_round(&second, &shared, Device::Honest).expect("a later attempt goes on");
    assert_eq!(
        resumed.outputs[0].script_pubkey,
        Some(expected_script(&resumed, &[&first, &second]))
    );
}
