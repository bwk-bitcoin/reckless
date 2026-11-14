// ws-plaude/silent#114: registerDescriptor on a QR key shows the Descriptor
// Registration request in the key's QR window, and answers only with the device's
// answer: closing the window answers cancelled, never registered.
#include "modules/keys/KeysModule.h"
#include "modules/keys/flow/SigningFlow.h"
#include "qr/QrDisplay.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QTimer>

#include <common.h>
#include <memory>
#include <optional>

namespace smoke {
namespace {

void require(bool condition, const char *message) {
    if (!condition) {
        qFatal("QR registration smoke: %s", message);
    }
}

// The key a QR device holds, and a wallet it is in (the Rust exchange tests' policy).
const char *const FINGERPRINT = "73c5da0a";
const char *const POLICY =
    "tr(musig([73c5da0a/87h/1h/0h]tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWxfTkA6bHNJ3CHUEtALQ"
    "dkNeixNz4446PcAmw4WKcj3mV2vb29H7sg9EPzbyCU1y2merw,[b8688df1/87h/1h/0h]"
    "tpubDC44ZFebbFm5ZXnG5Xt8k9PpdSZXUQ4HyuU8e8u5zfutYuu8EW4MLKS54EFTfGYgeqt7P2jEEd1iCF5kSPi7Xrj"
    "6EZcsStCcAjPy97DSiLb)/<0;1>/*)";

// Records what the bus answers the request.
class BusSpy final : public QObject {
    Q_OBJECT

public:
    int registered = 0;
    int cancelled = 0;
    int errors = 0;

public slots:

    void onRegistered([[maybe_unused]] ReqId req_id, [[maybe_unused]] const QString &fingerprint) {
        ++registered;
    }

    void onCancelled([[maybe_unused]] ReqId req_id) {
        ++cancelled;
    }

    void onError([[maybe_unused]] std::optional<ReqId> req_id,
                 [[maybe_unused]] const QString &message, [[maybe_unused]] plugin::SignError kind) {
        ++errors;
    }
};

// Looks at the registration window once its exec() shows it, then closes it.
class WindowProbe final : public QObject {
    Q_OBJECT

public:
    explicit WindowProbe(const BusSpy &spy) : m_spy(spy) {
        connect(&m_timer, &QTimer::timeout, this, &WindowProbe::onTick, qontrol::UNIQUE);
        m_timer.start(20);
    }

    bool seen = false;
    QString title;
    bool showsCode = false;
    bool answeredBefore = true;

public slots:

    void onTick() {
        auto *flow = qobject_cast<keys::flow::SigningFlow *>(QApplication::activeModalWidget());
        if (flow == nullptr || !flow->isVisible()) {
            return;
        }
        m_timer.stop();
        seen = true;
        title = flow->windowTitle();
        auto *display = flow->findChild<qr::QrDisplay *>();
        showsCode = display != nullptr && display->isVisible();
        answeredBefore = m_spy.registered + m_spy.cancelled + m_spy.errors > 0;
        flow->reject();
    }

private:
    const BusSpy &m_spy;
    QTimer m_timer;
};

} // namespace

void qrRegistrationSmoke() {
    Theme::get()->apply();
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    require(module->rust()->add_key(FINGERPRINT, "QR device").is_ok, "the QR key is added");
    require(module->rust()->add_route(FINGERPRINT, KeyRouteKind::Qr).is_ok,
            "the key's QR route is added");
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::descriptorRegistered, &spy,
                     &BusSpy::onRegistered, qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::cancelled, &spy, &BusSpy::onCancelled,
                     qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    WindowProbe probe(spy);
    // Runs the window: returns once the probe closed it.
    module->registerDescriptor(41, QString::fromLatin1(FINGERPRINT), QString::fromLatin1(POLICY));
    require(probe.seen, "registering on a QR key opens its QR window");
    require(probe.title == QStringLiteral("Show Registration Request"),
            "the window shows the registration request");
    require(probe.showsCode, "the window shows the request's QR code");
    require(!probe.answeredBefore, "nothing is answered before the device's answer");
    require(spy.registered == 0 && spy.cancelled == 1 && spy.errors == 0,
            "closing the window answers cancelled, never registered");
}

} // namespace smoke

#include "qr_registration_smoke.moc"
