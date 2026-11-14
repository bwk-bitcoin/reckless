//! ws-plaude/silent#123: plain wallets paying a silent payment address, through the
//! keys module's real plan and hot signers. The sending keys hold no sp() descriptor:
//! their input keys give the BIP-375 ECDH shares. With one key, it gives the shares,
//! derives the output and signs in one answer. With two keys, each first gives its own
//! inputs' shares, the output is derived once both are in, and each key then signs.
//! Every case ends with valid signatures and the output script the recipient finds
//! with its scan key.
//!
//! The file shares one datadir, so each case uses its own network to keep the test
//! mnemonics' keys apart.

use std::str::FromStr;

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
use reckless::{KeyUnusableReason, Network as FfiNetwork};

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
