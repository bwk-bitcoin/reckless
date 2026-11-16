#pragma once

#include <QString>

#include <cstdint>

#include "modules/keys/flow/SigningFlow.h"
#include "qr/QrTypes.h"

namespace catalog {
class Button;
class Card;
class ChunkedAddress;
class Label;
class ModalActions;
class ModalStatus;
} // namespace catalog

namespace qr {
class QrDisplay;
class QrDisplayEngine;
class QrEngine;
struct QrFrame;
} // namespace qr

namespace keys::flow {

class CameraStep;
class VerifyResultView;

// Signs, checks an address or fetches a descriptor over QR codes: shows the request
// with its tuning controls, scans the device's answer back, and for an address shows
// what the device said about it.
class QrRouteFlow final : public SigningRouteFlow {
    Q_OBJECT

public:
    QrRouteFlow(KeysModule *module, SigningFlow::Request request, FlowRow row, QString psbt);
    ~QrRouteFlow() override;
    // Shows the request.
    void start() override;

public slots:
    void onBackClicked();
    void onNextClicked();
    void onQrSigned(const QString &psbt_v2_hex);
    void onMusigPrepared();
    void onQrVerified(bool matched);
    void onQrRegistered(bool registered, bool stored, const QString &proof_hex);
    void onQrUnregistered();
    void onQrSpAccount(const QString &descriptor, const QList<qr::QrXpub> &xpubs);
    void onQrXpubs(const QString &fingerprint, const QList<qr::QrXpub> &xpubs,
                   const qr::QrDevice &device);
    void onQrError(qr::QrError kind, const QString &message, quint8 device_code);
    void onRequestShown(const QByteArray &bytes);
    void onReplyRead(const QByteArray &bytes, bool accepted, const QString &note);
    void onQrSettingsClicked();
    void onRefusedCloseClicked();
    void onQrFrame(const qr::QrFrame &frame);

protected:
    // The view on display: Back and the primary action act on it.
    enum class View : std::uint8_t { Display, Camera, VerifyResult, Refused };

    void init();
    void doConnect();
    void view();

    // QR code view
    void initDisplay();
    void connectDisplay();
    [[nodiscard]] auto viewDisplay() -> QWidget *;
    void showDisplay();
    // The steppers' levels to the engine.

    // Camera view
    void initCamera();
    void connectCamera();
    void showCamera();
    void hideCamera();

    // Verify result view
    void initVerifyResult();
    void connectVerifyResult();
    void showVerifyResult(SigningFlow::VerifyResult result);
    void hideVerifyResult();

    // Refused view: the device's own refusal of the request, its reason and Close
    // (ws-plaude/silent#116).
    void initRefused();
    void connectRefused();
    void showRefused(const QString &reason);
    void hideRefused();

    // Shared
    void stop();

private:
    View m_view = View::Display;
    qr::QrEngine *m_qr_engine = nullptr;

    qr::QrDisplayEngine *m_qr_display_engine = nullptr;
    catalog::Label *m_qr_hint = nullptr;
    catalog::ChunkedAddress *m_qr_address = nullptr;
    catalog::Card *m_qr_address_card = nullptr;
    qr::QrDisplay *m_qr_display = nullptr;
    catalog::Button *m_qr_settings = nullptr;
    catalog::Button *m_qr_next = nullptr;
    catalog::ModalActions *m_qr_actions = nullptr;
    QWidget *m_qr_step = nullptr;

    CameraStep *m_camera = nullptr;

    VerifyResultView *m_result = nullptr;

    catalog::ModalStatus *m_refused = nullptr;
    catalog::Button *m_refused_close = nullptr;
    catalog::ModalActions *m_refused_actions = nullptr;
};

} // namespace keys::flow
