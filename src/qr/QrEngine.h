#pragma once

#include "qr/QrTypes.h"

#include <QHash>
#include <QList>
#include <QObject>
#include <QString>
#include <QStringList>

#include <reckless.h>

namespace qr {

// A QR protocol codec: turns the exchanges a caller asks for into request payloads
// (request()), and the payloads scanned back into their answer or an error. Framing
// and scanning the payloads is the transport engines' business. One exchange at a
// time: each request ends the one in progress.
class QrEngine : public QObject {
    Q_OBJECT

public:
    explicit QrEngine(QObject *parent = nullptr);
    // Each path is written m/...
    virtual void getXpubs(const QStringList &paths) = 0;
    // The silent payment account: its sp() descriptor, with its taproot and segwit
    // sub-accounts' xpubs.
    virtual void getSpAccount() = 0;
    // To the device of the key `fingerprint`: the request carries what that key's
    // recorded registration of `descriptor` needs (ws-plaude/silent#117).
    virtual void sign(const QString &fingerprint, const QString &psbt_v2_hex,
                      const QString &descriptor) = 0;
    // A cached MuSig preparation: public nonces for a fresh cache session, bound to
    // no transaction.
    virtual void prepareMusig(const QString &fingerprint, const QString &descriptor) = 0;
    // The first signature request of a prepared cache session: the attempt's sessions
    // are allocated durably before the request is shown. `routes` names every pending
    // signer's route, so the allocation binds all of them.
    virtual void signMusig(const QString &fingerprint, const QString &psbt_v2_hex,
                           const QString &descriptor,
                           const QHash<QString, KeyRouteKind> &routes) = 0;
    virtual void verifyAddress(const QString &fingerprint, const QString &descriptor,
                               const QString &path, const QString &address) = 0;
    // Asks the device to register the wallet `descriptor` (ws-plaude/silent#114).
    virtual void registerDescriptor(const QString &descriptor) = 0;
    // Asks whether the device holds the wallet `descriptor` (ws-plaude/silent#115):
    // answered through descriptorRegistered too, `registered` saying whether it does.
    virtual void checkRegistration(const QString &descriptor) = 0;
    // Ends the exchange: a late answer is dropped.
    virtual void stop() = 0;

signals:
    void request(const qr::QrRequest &request);
    // One xpub per path asked, in the order asked.
    void xpubs(const QString &fingerprint, const QList<qr::QrXpub> &xpubs,
               const qr::QrDevice &device);
    void spAccount(const QString &descriptor, const QList<qr::QrXpub> &xpubs);
    void signedPsbt(const QString &psbt_v2_hex);
    // The prepared answer checked out and is in the cache.
    void noncesPrepared();
    void addressVerified(bool matched);
    // The device's registration answer: `stored` when it kept the wallet itself, else
    // `proof_hex` is the proof of registration to keep (empty when it gave none).
    void descriptorRegistered(bool registered, bool stored, const QString &proof_hex);
    // `device_code` is the device's bipqr error code when it refused the request
    // (DeviceRefused, or MusigSession for its 0x0D), else 0 (ws-plaude/silent#126).
    void error(qr::QrError kind, const QString &message, quint8 device_code = 0);

public slots:
    virtual void response(const qr::QrResponse &response) = 0;
};

} // namespace qr
