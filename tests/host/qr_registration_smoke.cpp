// ws-plaude/silent#114: registerDescriptor on a QR key shows the Descriptor
// Registration request in the key's QR window, and answers only with the device's
// answer: closing the window answers cancelled, never registered.
// ws-plaude/silent#125: the window does not block the rest of the app, one at a time.
// ws-plaude/silent#115: checkDescriptorRegistered on a QR key shows the registration
// check there too, never a "disconnected" error about a device that has no connection.
#include "modules/keys/KeysModule.h"
#include "modules/keys/flow/SigningFlow.h"
#include "qr/QrDisplay.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <functional>

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
    int checked = 0;
    int cancelled = 0;
    int errors = 0;

public slots:

    void onRegistered([[maybe_unused]] ReqId req_id, [[maybe_unused]] const QString &fingerprint) {
        ++registered;
    }

    void onChecked([[maybe_unused]] ReqId req_id, [[maybe_unused]] bool registered) {
        ++checked;
    }

    void onCancelled([[maybe_unused]] ReqId req_id) {
        ++cancelled;
    }

    void onError([[maybe_unused]] std::optional<ReqId> req_id,
                 [[maybe_unused]] const QString &message, [[maybe_unused]] plugin::SignError kind) {
        ++errors;
    }
};

// The keys flow windows open now.
auto openFlows() -> QList<keys::flow::SigningFlow *> {
    QList<keys::flow::SigningFlow *> flows;
    for (auto *widget : QApplication::topLevelWidgets()) {
        if (auto *flow = qobject_cast<keys::flow::SigningFlow *>(widget);
            flow != nullptr && flow->isVisible()) {
            flows.append(flow);
        }
    }
    return flows;
}

void pump(int ms) {
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
}

// The keys flow window the last call opened, once it shows.
auto waitForFlow() -> keys::flow::SigningFlow * {
    QElapsedTimer timer;
    timer.start();
    while (openFlows().isEmpty() && timer.elapsed() < 5000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    return openFlows().isEmpty() ? nullptr : openFlows().first();
}

// Checks the window `call` opened, then closes it: it answers cancelled.
void checkWindow(BusSpy &spy, keys::flow::SigningFlow *flow, const QString &title,
                 const std::function<void()> &second_call) {
    require(flow != nullptr, "the call on a QR key opens its QR window");
    require(flow->windowTitle() == title, "the window shows the request asked");
    auto *display = flow->findChild<qr::QrDisplay *>();
    require(display != nullptr && display->isVisible(), "the window shows the request's QR code");
    require(spy.registered + spy.checked + spy.cancelled + spy.errors == 0,
            "nothing is answered before the device's answer");
    // ws-plaude/silent#125: the window leaves the rest of the app usable, a plugin's tab
    // included, and stays one at a time.
    require(!flow->isModal() && flow->windowModality() == Qt::NonModal &&
                QApplication::activeModalWidget() == nullptr,
            "the keys window blocks nothing behind it");
    second_call();
    require(spy.errors == 1 && openFlows().size() == 1,
            "a second keys call while one is open is refused, never two windows");
    spy.errors = 0;
    QPointer<keys::flow::SigningFlow> closed = flow;
    flow->reject();
    pump(200);
    require(spy.registered == 0 && spy.checked == 0 && spy.cancelled == 1 && spy.errors == 0,
            "closing the window answers cancelled, never registered or disconnected");
    require(closed.isNull() && openFlows().isEmpty(), "the closed window is deleted");
    spy.cancelled = 0;
}

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
    QObject::connect(module->bus(), &keys::KeysBus::registrationChecked, &spy, &BusSpy::onChecked,
                     qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::cancelled, &spy, &BusSpy::onCancelled,
                     qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    const auto fingerprint = QString::fromLatin1(FINGERPRINT);
    const auto policy = QString::fromLatin1(POLICY);
    // The call returns at once (ws-plaude/silent#125): the window opens over the app.
    module->registerDescriptor(41, fingerprint, policy);
    checkWindow(spy, waitForFlow(), QStringLiteral("Show Registration Request"),
                [&module, &fingerprint, &policy] {
                    module->checkDescriptorRegistered(43, fingerprint, policy);
                });
    module->checkDescriptorRegistered(42, fingerprint, policy);
    checkWindow(
        spy, waitForFlow(), QStringLiteral("Show Registration Check"),
        [&module, &fingerprint, &policy] { module->registerDescriptor(44, fingerprint, policy); });
}

} // namespace smoke

#include "qr_registration_smoke.moc"
