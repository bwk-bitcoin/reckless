//! The bipqr protocol codec: builds signing-flow requests as protocol messages, and
//! decodes and validates the matching responses. Framing the bytes is the transport's
//! business.
//!
//! `QrSession` owns the request id counter and remembers the one outstanding request,
//! so a decoded response is checked against what was actually asked before it is
//! accepted. Nonce cache MuSig requests are built and checked by bwk's QR MuSig host.

use std::str::FromStr;

use bipqr::{
    backend::{Active, Backend},
    ll::{
        decode, encode_request,
        request::{self, KeyKind, Scan, SpKeys},
        response, types, Message, MessageType, Request, RequestId, Response, SignResponseKind,
    },
};
use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    Network, Psbt,
};
use bwk_sp::{
    account::bip375,
    bwk_sign::{
        bwk_descriptor::{
            descriptor::{tr_path, wpkh_path},
            sp_descriptor::SpDescriptor,
        },
        qr_musig_host::merge_signatures_v2,
    },
    bwk_tx::bwk_psbt::{PsbtV2, TxModifiable},
    receiver::{scan_path, spend_path},
};

use crate::{
    config::sub_account,
    hwi,
    keys::{
        error::Error,
        hot::{sp_account, watch_only_sp_descriptor},
        musig_sessions::{
            Host, QrMusigAnswer, QrPreparationMaterial, QrSigningMaterial, PEER_CAPABILITIES,
        },
        psbt,
    },
};

/// What a `GetKeys` request asked for. Its response carries the keys in request
/// order and nothing else to pair them with.
enum KeysRequest {
    /// Every key public.
    Xpubs(Vec<DerivationPath>),
    SpAccount(SpAccountPaths),
}

/// The keys of a silent payment account: its spend key public and its scan key
/// private, then the taproot and segwit sub-accounts' xpubs.
struct SpAccountPaths {
    network: Network,
    account: ChildNumber,
    spend: DerivationPath,
    scan: DerivationPath,
    taproot: DerivationPath,
    segwit: DerivationPath,
}

impl KeysRequest {
    /// The keys asked for, in request order.
    fn keys(&self) -> Vec<(DerivationPath, KeyKind)> {
        match self {
            Self::Xpubs(paths) => paths
                .iter()
                .map(|path| (path.clone(), KeyKind::Public))
                .collect(),
            Self::SpAccount(paths) => vec![
                (paths.spend.clone(), KeyKind::Public),
                (paths.scan.clone(), KeyKind::Private),
                (paths.taproot.clone(), KeyKind::Public),
                (paths.segwit.clone(), KeyKind::Public),
            ],
        }
    }
}

/// The nonce cache exchange an outstanding request belongs to: bwk's host that built
/// it, which checks the answer, the session it names, and the PSBT a Signing request
/// carried.
struct MusigOutstanding {
    host: Host,
    session_id: [u8; 4],
    sent: Option<Psbt>,
}

impl MusigOutstanding {
    fn answer(self, payload: &[u8]) -> QrMusigAnswer {
        QrMusigAnswer {
            host: self.host,
            session_id: self.session_id,
            sent: self.sent,
            payload: payload.to_vec(),
        }
    }
}

/// What the next response has to match. `keys` is `None` for every request but
/// `GetKeys`. Read back by `validate_response` to check a decoded response against
/// what was actually asked.
struct Outstanding {
    id: RequestId,
    message_type: MessageType,
    keys: Option<KeysRequest>,
    /// The address a `VerifyAddress` request asked the device to confirm, so the
    /// response can be compared against it. `None` for every other request.
    expected_address: Option<String>,
    /// The original v2 PSBT bytes a `Sign` request carried, so `validate_signed` merges
    /// the device's answer into it instead of trusting the returned bytes as-is. `None`
    /// for every other request kind.
    original_psbt_v2: Option<Vec<u8>>,
    /// The PSBT a `Sign` request asking for the signatures-only reply sent, as v2 so
    /// it takes silent payment entries, which the reply's entries merge into. `None`
    /// when the request asked for a full PSBT.
    signatures_into: Option<PsbtV2>,
    /// The nonce cache exchange of a Nonce Preparation request or of a Signing
    /// request naming a cached session. `None` for every other request.
    musig: Option<MusigOutstanding>,
}

/// Allocates request ids, builds the five signing-flow requests, and remembers the one
/// outstanding request a response is checked against.
#[derive(Default)]
pub struct QrSession {
    counter: u16,
    outstanding: Option<Outstanding>,
}

impl QrSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears any outstanding request and the id counter, for a network switch.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn outstanding_id(&self) -> Option<RequestId> {
        self.outstanding.as_ref().map(|outstanding| outstanding.id)
    }

    /// `RequestId([0, 0])` is never issued: it stays reserved for "no outstanding
    /// request" and for a signer's reply to a request it could not read. The first id
    /// is 1, and the counter skips 0 when it wraps.
    fn next_id(&mut self) -> RequestId {
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            self.counter = 1;
        }
        RequestId(self.counter.to_be_bytes())
    }

    pub fn get_xpubs(&mut self, paths: Vec<DerivationPath>) -> Result<QrRequest, Error> {
        if paths.is_empty() {
            return Err(Error::EmptyPathList);
        }
        self.get_keys(KeysRequest::Xpubs(paths))
    }

    /// Asks for the silent payment account in one request: the signer gives out its
    /// scan key, never its spend key, and the sp() descriptor is built from them here.
    pub fn get_sp_account(&mut self, network: Network) -> Result<QrRequest, Error> {
        let account = sp_account()?;
        let sub_account = sub_account();
        let paths = SpAccountPaths {
            network,
            account,
            spend: spend_path(network, account),
            scan: scan_path(network, account),
            taproot: tr_path(network, sub_account).expect("the sub-account is hardened"),
            segwit: wpkh_path(network, sub_account).expect("the sub-account is hardened"),
        };
        self.get_keys(KeysRequest::SpAccount(paths))
    }

    fn get_keys(&mut self, keys: KeysRequest) -> Result<QrRequest, Error> {
        let requests = keys
            .keys()
            .iter()
            .map(|(path, kind)| request::KeyRequest {
                derivation_path: Active::to_ll_path(path),
                kind: *kind,
            })
            .collect();
        let body = request::Body::GetKeys(request::GetKeys { keys: requests });
        self.issue(body, Some(keys), None, None)
    }

    pub fn register_descriptor(&mut self, descriptor: &str) -> Result<QrRequest, Error> {
        let body = request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: hwi::wallet_name(descriptor),
            descriptor: Some(request::DescriptorBody::Bip380(descriptor.to_string())),
        });
        self.issue(body, None, None, None)
    }

    /// Asks the device to forget the wallet `descriptor` (bipqr Unregister Descriptor,
    /// ws-plaude/silent#130): its alias alone. The answer is an Unregistered.
    pub fn unregister_descriptor(&mut self, descriptor: &str) -> Result<QrRequest, Error> {
        let body = request::Body::UnregisterDescriptor(request::UnregisterDescriptor {
            descriptor_alias: hwi::wallet_name(descriptor),
        });
        self.issue(body, None, None, None)
    }

    /// Asks whether the device holds the wallet `descriptor`: the registration request
    /// with its alias and no descriptor body (bipqr's registration check,
    /// ws-plaude/silent#115). The answer is a Registration.
    pub fn check_registration(&mut self, descriptor: &str) -> Result<QrRequest, Error> {
        let body = request::Body::RegisterDescriptor(request::RegisterDescriptor {
            descriptor_alias: hwi::wallet_name(descriptor),
            descriptor: None,
        });
        self.issue(body, None, None, None)
    }

    /// A silent payment address is asked for with its account's keys instead of the
    /// sp() descriptor, which holds the scan secret: `path` is then its label, empty
    /// for the account's address.
    pub fn verify_address(
        &mut self,
        descriptor: &str,
        path: DerivationPath,
        address: String,
    ) -> Result<QrRequest, Error> {
        self.verify_address_registered(descriptor, path, address, &QrRegistration::Unknown)
    }

    /// [`QrSession::verify_address`] to a device whose registration of `descriptor` is
    /// `registration` (ws-plaude/silent#117).
    pub fn verify_address_registered(
        &mut self,
        descriptor: &str,
        path: DerivationPath,
        address: String,
        registration: &QrRegistration,
    ) -> Result<QrRequest, Error> {
        let body = match SpDescriptor::from_str(descriptor) {
            Ok(sp) => request::DescriptorBody::SpKeys(sp_keys(&sp)?),
            Err(_) => request::DescriptorBody::Bip380(descriptor.to_string()),
        };
        let (descriptor_body, proof) = registration.carried(body);
        let body = request::Body::VerifyAddress(request::VerifyAddress {
            descriptor_alias: hwi::wallet_name(descriptor),
            derivation_path: Active::to_ll_path(&path),
            address: Some(address.clone()),
            descriptor: descriptor_body,
            proof,
        });
        self.issue(body, None, Some(address), None)
    }

    pub fn sign(
        &mut self,
        descriptors: &[String],
        psbt_v2_bytes: &[u8],
    ) -> Result<QrRequest, Error> {
        self.sign_registered(descriptors, psbt_v2_bytes, &|_| QrRegistration::Unknown)
    }

    /// [`QrSession::sign`] to a device whose registration of each descriptor is
    /// `registration(descriptor)` (ws-plaude/silent#117).
    pub fn sign_registered(
        &mut self,
        descriptors: &[String],
        psbt_v2_bytes: &[u8],
        registration: &dyn Fn(&str) -> QrRegistration,
    ) -> Result<QrRequest, Error> {
        let descriptors = descriptors
            .iter()
            .map(|descriptor| {
                let (body, proof) = registration(descriptor)
                    .carried(request::DescriptorBody::Bip380(descriptor.clone()));
                request::Descriptor {
                    alias: hwi::wallet_name(descriptor),
                    descriptor: body,
                    proof,
                }
            })
            .collect();
        // Round 1 goes out without nonces: a device decides its round from its own
        // nonce, and the merge keeps the nonces already gathered.
        let mut wire = psbt::parse_v2(psbt_v2_bytes)?;
        let musig = psbt::has_musig_inputs(&wire)?;
        let stripped = psbt::strip_musig_round1(&mut wire)?;
        // A silent-payment PSBT needs its input tweaks and ECDH shares, which a v0
        // conversion drops, so it goes over the wire as v2, unchanged unless stripped.
        // A plain hardware signer over QR still expects v0.
        let payload = match (psbt::has_sp_artifacts(&wire)?, stripped) {
            (false, _) => wire
                .clone()
                .into_bitcoin_psbt()
                .map_err(|e| Error::PsbtSerialize(e.to_string()))?
                .serialize(),
            (true, true) => wire
                .serialize()
                .map_err(|e| Error::PsbtSerialize(e.to_string()))?,
            (true, false) => psbt_v2_bytes.to_vec(),
        };
        // A MuSig PSBT, sent as v0 or v2, asks for the signatures-only reply, merged
        // into what was sent.
        let signatures_into = musig.then_some(wire);
        let want_kind = match signatures_into {
            Some(_) => SignResponseKind::Signatures,
            None => SignResponseKind::Psbt,
        };
        let body = request::Body::Sign(request::Sign {
            descriptors,
            psbt: payload,
            want_kind: Some(want_kind),
            accept_trimmed: false,
        });
        let request = self.issue(body, None, None, Some(psbt_v2_bytes.to_vec()))?;
        if let Some(outstanding) = self.outstanding.as_mut() {
            outstanding.signatures_into = signatures_into;
        }
        Ok(request)
    }

    /// A nonce preparation, built by bwk's host from a session record already
    /// durable in the cache, so a lost exchange never takes a session.
    pub fn prepare_nonces(&mut self, material: QrPreparationMaterial) -> Result<QrRequest, Error> {
        let QrPreparationMaterial {
            mut host,
            session_id,
            issuance,
        } = material;
        let id = self.next_id();
        let message = host
            .extend_request(PEER_CAPABILITIES, id, session_id, issuance)
            .map_err(|e| Error::QrMusigHost(e.to_string()))?;
        let musig = MusigOutstanding {
            host,
            session_id,
            sent: None,
        };
        Ok(self.issue_musig(id, MessageType::NoncePreparation, message, musig))
    }

    /// The first signature request of an allocated session, built by bwk's host: the
    /// PSBT carries the complete participant nonce transcript and names the session.
    /// It asks for the signatures-only reply, which bwk's host verifies and merges.
    pub fn sign_nonce_cache(&mut self, material: QrSigningMaterial) -> Result<QrRequest, Error> {
        let QrSigningMaterial {
            mut host,
            session_id,
            descriptor,
            psbt,
        } = material;
        let id = self.next_id();
        let message = host
            .sign_request(
                PEER_CAPABILITIES,
                id,
                session_id,
                vec![descriptor],
                &psbt,
                Some(SignResponseKind::Signatures),
            )
            .map_err(|e| Error::QrMusigHost(e.to_string()))?;
        let musig = MusigOutstanding {
            host,
            session_id,
            sent: Some(sent_psbt(&message)?),
        };
        Ok(self.issue_musig(id, MessageType::Signing, message, musig))
    }

    /// Makes an encoded nonce cache request the outstanding one.
    fn issue_musig(
        &mut self,
        id: RequestId,
        message_type: MessageType,
        message: Vec<u8>,
        musig: MusigOutstanding,
    ) -> QrRequest {
        self.outstanding = Some(Outstanding {
            id,
            message_type,
            keys: None,
            expected_address: None,
            original_psbt_v2: None,
            signatures_into: None,
            musig: Some(musig),
        });
        QrRequest { id, message }
    }

    /// Encodes the request and makes it the outstanding one.
    fn issue(
        &mut self,
        body: request::Body,
        keys: Option<KeysRequest>,
        expected_address: Option<String>,
        original_psbt_v2: Option<Vec<u8>>,
    ) -> Result<QrRequest, Error> {
        let id = self.next_id();
        let message_type = body.message_type();
        let message = encode_request(&Request { id, body })?;
        self.outstanding = Some(Outstanding {
            id,
            message_type,
            keys,
            expected_address,
            original_psbt_v2,
            signatures_into: None,
            musig: None,
        });
        Ok(QrRequest { id, message })
    }

    /// Decodes a pasted or scanned payload and validates it against the outstanding
    /// request.
    pub fn decode_response(&mut self, bytes: &[u8]) -> Result<QrResponse, Error> {
        match decode(bytes)? {
            Message::Request(_) => Err(Error::PayloadIsRequest),
            Message::Response(response) => self.validate_response(response, bytes),
        }
    }

    /// A nonce cache answer goes, as its `payload`, to the host that asked it: the
    /// host checks it, and drops the session of a refusal for it.
    fn validate_response(
        &mut self,
        response: Response,
        payload: &[u8],
    ) -> Result<QrResponse, Error> {
        let Some(outstanding) = self.outstanding.as_ref() else {
            return Err(Error::NoOutstandingRequest);
        };
        // A signer that cannot read a request answers under the reserved id, which no
        // request carries: the request stays outstanding for a new scan.
        if let response::Body::Error(e) = &response.body {
            if e.message_type == MessageType::UnreadableRequest
                && response.id == RequestId::UNREADABLE_REQUEST
            {
                return Err(Error::SignerUnreadableRequest {
                    message: e.message.clone(),
                });
            }
        }
        if response.id != outstanding.id {
            return Err(Error::RequestIdMismatch {
                expected: hex_id(outstanding.id),
                got: hex_id(response.id),
            });
        }
        let expected_type = outstanding.message_type;
        let musig_session = outstanding.musig.as_ref().map(|musig| musig.session_id);
        let musig = musig_session.is_some();
        let body = response.body;
        match &body {
            response::Body::Error(e) if musig && e.error == response::Error::MusigSession => {}
            response::Body::Error(e) => return Err(refusal(e)),
            body if body.message_type() != expected_type => {
                return Err(Error::ResponseKindMismatch {
                    expected: expected_type,
                    got: body.message_type(),
                })
            }
            _ => {}
        }
        // Checked here too, so a scan of another exchange leaves this one open.
        if let (response::Body::NoncesPrepared(prepared), Some(session_id)) = (&body, musig_session)
        {
            validate_nonces_prepared(prepared, session_id)?;
        }
        if musig {
            let answer = self
                .outstanding
                .take()
                .and_then(|outstanding| outstanding.musig)
                .expect("checked above")
                .answer(payload);
            return Ok(match expected_type {
                MessageType::NoncePreparation => QrResponse::MusigPrepared(answer),
                _ => QrResponse::MusigSignedPsbt(answer),
            });
        }
        let outstanding = self.outstanding.as_ref().expect("checked above");
        let got_type = body.message_type();
        let parsed = match body {
            response::Body::Keys(keys) => {
                let requested = outstanding
                    .keys
                    .as_ref()
                    .expect("a GetKeys request always records its keys");
                validate_keys(keys, requested)?
            }
            response::Body::Signed(signed) => validate_signed(
                signed,
                outstanding.original_psbt_v2.as_deref(),
                outstanding.signatures_into.as_ref(),
            )?,
            response::Body::Registration(registration) => registration_response(registration),
            response::Body::Unregistered(unregistered) => QrResponse::Unregistered {
                alias: unregistered.descriptor_alias,
            },
            response::Body::AddressUri(address_uri) => {
                validate_address_uri(address_uri, outstanding.expected_address.clone())?
            }
            // Never asked for: Get Info answers no request this session sends, and
            // nonce preparations are answered to the host above.
            response::Body::Info(_) | response::Body::NoncesPrepared(_) => {
                return Err(Error::ResponseKindMismatch {
                    expected: expected_type,
                    got: got_type,
                })
            }
            response::Body::Error(_) => unreachable!("error responses are handled above"),
        };

        self.outstanding = None;
        Ok(parsed)
    }
}

/// The error a signer's refusal surfaces as.
fn refusal(error: &response::ErrorBody) -> Error {
    match error.error {
        response::Error::MusigSession => Error::MusigSession,
        response::Error::AlreadyRegistered => Error::AlreadyRegistered {
            message_type: error.message_type,
            message: error.message.clone(),
        },
        response::Error::UnsupportedOperation => Error::SignerUnsupported {
            message_type: error.message_type,
            message: error.message.clone(),
        },
        response::Error::NetworkMismatch => Error::SignerNetworkMismatch {
            message: error.message.clone(),
        },
        code => Error::SignerRefused {
            message_type: error.message_type,
            code,
            message: error.message.clone(),
        },
    }
}

/// A nonce preparation answer announcing a new session must name the one it was
/// asked for. One answered from a held session names none.
fn validate_nonces_prepared(
    prepared: &response::NoncesPrepared,
    session_id: [u8; 4],
) -> Result<(), Error> {
    if prepared
        .session
        .is_some_and(|session| session.session_id != session_id)
    {
        return Err(Error::MusigSessionMismatch);
    }
    Ok(())
}

/// The PSBT a Signing request carries.
fn sent_psbt(message: &[u8]) -> Result<Psbt, Error> {
    match decode(message)? {
        Message::Request(Request {
            body: request::Body::Sign(sign),
            ..
        }) => Psbt::deserialize(&sign.psbt).map_err(|e| Error::PsbtParse(e.to_string())),
        _ => Err(Error::QrMusigHost(
            "the host built no Signing request".to_string(),
        )),
    }
}

/// The device's bipqr error code when `payload` is its error response, as a MuSig2
/// answer handed to the cache may be (ws-plaude/silent#135).
pub fn device_error_code(payload: &[u8]) -> Option<u8> {
    match decode(payload) {
        Ok(Message::Response(Response {
            body: response::Body::Error(error),
            ..
        })) => Some(u8::from(error.error)),
        _ => None,
    }
}

/// A decoded and validated signing-flow QR response.
#[derive(Debug)]
pub enum QrResponse {
    Xpubs {
        fingerprint: Fingerprint,
        xpubs: Vec<(DerivationPath, Xpub)>,
        vendor: String,
        model: String,
        version: String,
        capabilities: u32,
    },
    /// The device's answer to a descriptor registration. `stored` says whether it kept
    /// the registration itself; when it did not, `proof` is the proof of registration a
    /// later request must carry (ws-plaude/silent#114).
    Registration {
        alias: String,
        registered: bool,
        stored: Option<bool>,
        proof: Option<Vec<u8>>,
    },
    /// The device no longer holds the wallet `alias` (ws-plaude/silent#130).
    Unregistered { alias: String },
    /// Whether the device's independently derived address matched the one the
    /// caller asked it to confirm.
    AddressVerified(bool),
    /// The original v2 PSBT the sign request carried, with the device's signatures
    /// merged in. Always v2, even for a plain (non-SP) sign request that was sent to
    /// the device as v0.
    SignedPsbt(Vec<u8>),
    /// A silent payment account: its watch-only sp() descriptor, built from the keys
    /// the signer gave, and its taproot and segwit sub-accounts' xpubs.
    SpAccount {
        descriptor: String,
        fingerprint: Fingerprint,
        xpubs: Vec<(DerivationPath, Xpub)>,
    },
    /// A peer's answer to a nonce preparation, or its refusal for the session, for
    /// the host and the cache to accept.
    MusigPrepared(QrMusigAnswer),
    /// A peer's answer to a Signing request naming a cached session, or its refusal
    /// for the session, for the host and the cache to accept.
    MusigSignedPsbt(QrMusigAnswer),
}

/// A `Keys` response must carry one key per requested key, each of the requested kind.
fn validate_keys(keys: response::Keys, requested: &KeysRequest) -> Result<QrResponse, Error> {
    let requested_keys = requested.keys();
    if keys.keys.len() != requested_keys.len() {
        return Err(Error::XpubCountMismatch {
            requested: requested_keys.len(),
            returned: keys.keys.len(),
        });
    }
    let fingerprint = Active::from_ll_fingerprint(&keys.fingerprint);
    match requested {
        KeysRequest::Xpubs(paths) => {
            let mut xpubs = Vec::with_capacity(paths.len());
            for (path, key) in paths.iter().zip(keys.keys.iter()) {
                xpubs.push((path.clone(), public_key(key, path)?));
            }
            Ok(QrResponse::Xpubs {
                fingerprint,
                xpubs,
                vendor: keys.vendor,
                model: keys.model,
                version: format!(
                    "{}.{}.{}",
                    keys.version.major, keys.version.minor, keys.version.patch
                ),
                capabilities: keys.capabilities.0,
            })
        }
        KeysRequest::SpAccount(paths) => {
            let keys = keys
                .keys
                .try_into()
                .expect("the key count is checked above");
            sp_account_response(fingerprint, keys, paths)
        }
    }
}

/// `keys` are in `SpAccountPaths` request order.
fn sp_account_response(
    fingerprint: Fingerprint,
    [spend, scan, taproot, segwit]: [types::ExtendedKey; 4],
    paths: &SpAccountPaths,
) -> Result<QrResponse, Error> {
    let spend = public_key(&spend, &paths.spend)?;
    let scan = private_key(&scan, &paths.scan)?;
    let taproot = public_key(&taproot, &paths.taproot)?;
    let segwit = public_key(&segwit, &paths.segwit)?;
    let descriptor = watch_only_sp_descriptor(
        fingerprint,
        paths.network,
        paths.account,
        scan.private_key,
        spend.public_key,
    );
    Ok(QrResponse::SpAccount {
        descriptor: descriptor.to_string(),
        fingerprint,
        xpubs: vec![
            (paths.taproot.clone(), taproot),
            (paths.segwit.clone(), segwit),
        ],
    })
}

/// The xpub the signer returned for a public key request at `path`.
fn public_key(key: &types::ExtendedKey, path: &DerivationPath) -> Result<Xpub, Error> {
    Active::from_ll_xpub(key).map_err(|e| match Active::from_ll_xpriv(key) {
        Ok(_) => Error::KeyKindMismatch {
            path: path.clone(),
            requested: KeyKind::Public,
        },
        Err(_) => Error::from(e),
    })
}

/// The xpriv the signer returned for a private key request at `path`.
fn private_key(key: &types::ExtendedKey, path: &DerivationPath) -> Result<Xpriv, Error> {
    Active::from_ll_xpriv(key).map_err(|e| match Active::from_ll_xpub(key) {
        Ok(_) => Error::KeyKindMismatch {
            path: path.clone(),
            requested: KeyKind::Private,
        },
        Err(_) => Error::from(e),
    })
}

/// Merges the device's answer into `original_psbt_v2` with the same helper USB
/// signing uses, so both paths always hand back v2 bytes with the original's reckless
/// payment fields intact. `original_psbt_v2` is `None` for a signed response to a
/// request that carried no PSBT, which is refused rather than trusted as-is. A
/// signatures-only reply is accepted only for a request that asked for one: its
/// entries go into the PSBT sent, `signatures_into`, then merge like a full answer.
fn validate_signed(
    signed: response::Signed,
    original_psbt_v2: Option<&[u8]>,
    signatures_into: Option<&PsbtV2>,
) -> Result<QrResponse, Error> {
    let original = original_psbt_v2.ok_or(Error::InvalidSignedPsbt)?;
    let bytes = match (signed, signatures_into) {
        (response::Signed::Psbt(bytes), _) => bytes,
        (response::Signed::Signatures(entries), Some(sent)) => signatures_reply(sent, &entries)?,
        (response::Signed::Signatures(_), None) => return Err(Error::SignaturesUnsupported),
    };
    Ok(QrResponse::SignedPsbt(psbt::merge_signatures_bytes(
        original, &bytes,
    )?))
}

/// The PSBT `sent` with a signatures-only reply's `entries` merged in, serialized as
/// v2. Silent payment outputs the signer derived are not in the reply: their scripts
/// are completed from the merged ECDH shares, and the transaction frozen as the
/// signer froze it, so the merge checks the proofs, scripts and signatures as it
/// does for a full answer.
fn signatures_reply(sent: &PsbtV2, entries: &[response::SignatureEntry]) -> Result<Vec<u8>, Error> {
    let mut merged = merge_signatures_v2(sent.clone(), entries)
        .map_err(|e| Error::QrMusigHost(e.to_string()))?;
    // The outputs follow once every share is in; a key of several gives only its own
    // inputs' shares, the others' coming later (ws-plaude/silent#123). Each new share's
    // proof is checked now, not only once the outputs can be derived (#132).
    if psbt::sp_outputs_pending(sent)? {
        psbt::check_new_input_shares(sent, &merged)?;
        if psbt::sp_shares_complete(&merged)? {
            bip375::complete_output_scripts(&mut merged)
                .map_err(|e| Error::SpSignedInvalid(e.to_string()))?;
            merged.tx_modifiable = Some(TxModifiable::none());
        }
    }
    merged
        .serialize()
        .map_err(|e| Error::PsbtSerialize(e.to_string()))
}

fn registration_response(registration: response::Registration) -> QrResponse {
    QrResponse::Registration {
        alias: registration.descriptor_alias,
        registered: registration.registered,
        stored: registration.stored,
        proof: registration.proof,
    }
}

/// The keys a signer rebuilds an sp() descriptor's address from, with no secret: its
/// fingerprint and the BIP-352 spend and scan paths of its account.
fn sp_keys(descriptor: &SpDescriptor) -> Result<SpKeys, Error> {
    let (fingerprint, origin) = descriptor.origin().ok_or(Error::SpDescriptorNoOrigin)?;
    // The origin is the account, `352'/coin'/account'`, or a key under it.
    let steps: Vec<ChildNumber> = origin.clone().into();
    let purpose = ChildNumber::from_hardened_idx(352).expect("352 is a valid index");
    let (Some(&first), Some(&coin), Some(&account)) = (steps.first(), steps.get(1), steps.get(2))
    else {
        return Err(Error::SpAccountPath(origin));
    };
    if first != purpose || !coin.is_hardened() || !account.is_hardened() {
        return Err(Error::SpAccountPath(origin));
    }
    // The paths only tell mainnet (coin 0') from the test networks (coin 1').
    let network = match coin {
        ChildNumber::Hardened { index: 0 } => Network::Bitcoin,
        _ => Network::Testnet,
    };
    Ok(SpKeys {
        fingerprint: Active::to_ll_fingerprint(&fingerprint),
        spend_path: Active::to_ll_path(&spend_path(network, account)),
        scan: Scan::Path(Active::to_ll_path(&scan_path(network, account))),
    })
}

/// The device echoes back the address it independently derived as a BIP-321 URI,
/// never the bare address; comparing it against `expected_address` is the whole
/// point of the request.
fn validate_address_uri(
    address_uri: response::AddressUri,
    expected_address: Option<String>,
) -> Result<QrResponse, Error> {
    let expected = expected_address.ok_or(Error::MissingExpectedAddress)?;
    Ok(QrResponse::AddressVerified(uri_names_address(
        &address_uri.uri,
        &expected,
    )))
}

/// Whether the BIP-321 URI `uri` names `expected` (ws-plaude/silent#122): a silent
/// payment address is the `sp=` parameter (`bitcoin:?sp=sp1q...`), the path then being
/// only a fallback for wallets without silent payments; any other address is the path,
/// whatever query follows it.
pub fn uri_names_address(uri: &str, expected: &str) -> bool {
    let Some(rest) = uri
        .get(..8)
        .filter(|scheme| scheme.eq_ignore_ascii_case("bitcoin:"))
        .map(|_| &uri[8..])
    else {
        return false;
    };
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if is_sp_address(expected) {
        return query
            .split('&')
            .filter_map(|parameter| parameter.split_once('='))
            .any(|(key, value)| key.eq_ignore_ascii_case("sp") && same_address(value, expected));
    }
    !path.is_empty() && same_address(path, expected)
}

/// A silent payment address, by its human-readable part (BIP-352: `sp`, `tsp`).
fn is_sp_address(address: &str) -> bool {
    let lower = address.to_ascii_lowercase();
    lower.starts_with("sp1") || lower.starts_with("tsp1")
}

/// The same address: exactly, or in the other case for a bech32 address, which is
/// written all lower or all upper case. A base58 address only compares exactly.
fn same_address(found: &str, expected: &str) -> bool {
    if found == expected {
        return true;
    }
    let single_case =
        expected == expected.to_ascii_lowercase() || expected == expected.to_ascii_uppercase();
    single_case && expected.contains('1') && found.eq_ignore_ascii_case(expected)
}

/// Hex-encodes a request id for error messages.
fn hex_id(id: RequestId) -> String {
    id.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// How a device holds a wallet a request names (ws-plaude/silent#117).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrRegistration {
    /// No registration answer is recorded: the request carries the descriptor body.
    Unknown,
    /// The device kept the wallet: the request names its alias alone.
    Stored,
    /// The device gave this proof of registration instead of keeping the wallet: the
    /// request carries the descriptor body and the proof.
    Proof(Vec<u8>),
}

impl QrRegistration {
    /// The descriptor body and proof a request carries for this registration.
    fn carried(
        &self,
        body: request::DescriptorBody,
    ) -> (Option<request::DescriptorBody>, Option<Vec<u8>>) {
        match self {
            Self::Unknown => (Some(body), None),
            Self::Stored => (None, None),
            Self::Proof(proof) => (Some(body), Some(proof.clone())),
        }
    }
}

/// One request as issued: its id and the protocol message carrying it.
pub struct QrRequest {
    id: RequestId,
    message: Vec<u8>,
}

impl QrRequest {
    pub fn id(&self) -> RequestId {
        self.id
    }

    pub fn message(&self) -> &[u8] {
        &self.message
    }

    pub fn into_message(self) -> Vec<u8> {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_id_skips_zero_when_it_wraps() {
        let mut session = QrSession {
            counter: u16::MAX - 1,
            ..QrSession::default()
        };
        assert_eq!(session.next_id(), RequestId(u16::MAX.to_be_bytes()));
        assert_eq!(
            session.next_id(),
            RequestId([0, 1]),
            "0x0000 is never issued"
        );
    }
}

#[cfg(test)]
mod address_uri_tests {
    use super::uri_names_address;

    const WPKH: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const BASE58: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
    const SP: &str = "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const SP_LABEL_1: &str = "tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqah4hxfsjdwyaeel4g8x2npkj7qlvf2692l5760z5ut0ggnlrhdzsy3cvsj";

    #[test]
    fn a_plain_address_is_the_path() {
        assert!(uri_names_address(&format!("bitcoin:{WPKH}"), WPKH));
        assert!(uri_names_address(
            &format!("BITCOIN:{}", WPKH.to_uppercase()),
            WPKH
        ));
        assert!(uri_names_address(&format!("bitcoin:{BASE58}"), BASE58));
        assert!(!uri_names_address(
            &format!("bitcoin:{}", BASE58.to_lowercase()),
            BASE58
        ));
    }

    #[test]
    fn a_plain_address_with_a_query_is_the_path() {
        assert!(uri_names_address(
            &format!("bitcoin:{WPKH}?amount=0.1&label=x"),
            WPKH
        ));
    }

    #[test]
    fn a_silent_payment_address_is_the_sp_parameter() {
        assert!(uri_names_address(&format!("bitcoin:?sp={SP}"), SP));
        assert!(uri_names_address(
            &format!("bitcoin:?SP={}", SP.to_uppercase()),
            SP
        ));
        // The path is a fallback address, never the one compared.
        assert!(uri_names_address(&format!("bitcoin:{WPKH}?sp={SP}"), SP));
        assert!(!uri_names_address(&format!("bitcoin:{SP}"), SP));
    }

    #[test]
    fn a_labelled_silent_payment_address_verifies_the_same_way() {
        assert!(uri_names_address(
            &format!("bitcoin:?sp={SP_LABEL_1}"),
            SP_LABEL_1
        ));
        assert!(!uri_names_address(&format!("bitcoin:?sp={SP}"), SP_LABEL_1));
    }

    #[test]
    fn another_address_or_none_does_not_match() {
        assert!(!uri_names_address(&format!("bitcoin:{BASE58}"), WPKH));
        assert!(!uri_names_address(&format!("bitcoin:?sp={SP_LABEL_1}"), SP));
        assert!(!uri_names_address("bitcoin:", WPKH));
        assert!(!uri_names_address("bitcoin:?amount=1", SP));
        assert!(!uri_names_address(WPKH, WPKH));
    }
}
