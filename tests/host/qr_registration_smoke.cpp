// ws-plaude/silent#114: registerDescriptor on a QR key shows the Descriptor
// Registration request in the key's QR window, and answers only with the device's
// answer: closing the window answers cancelled, never registered.
// ws-plaude/silent#125: the window does not block the rest of the app, one at a time.
// ws-plaude/silent#115: checkDescriptorRegistered on a QR key shows the registration
// check there too, never a "disconnected" error about a device that has no connection.
// ws-plaude/silent#126: a device's refusal, over QR codes or USB, reaches the caller
// through the keys window as DeviceRefused with the device's own code.
#include "catalog/Button.h"
#include "interfaces/host.h"
#include "interfaces/instance.h"
#include "interfaces/signer.h"
#include "modules/keys/KeysModule.h"
#include "modules/keys/flow/SigningFlow.h"
#include "qr/QrDisplay.h"
#include "qr/QrEngine.h"
#include "qr/QrTypes.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QByteArray>
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
    plugin::SignError lastKind = plugin::SignError::Other;
    quint8 lastCode = 0;

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
                 [[maybe_unused]] const QString &message, plugin::SignError kind,
                 quint8 device_code) {
        ++errors;
        lastKind = kind;
        lastCode = device_code;
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

// A bipqr error response (ENCODING.md, Error response body): MAGIC, VERSION 1, the
// response-error MSG_TYPE of `type`, the echoed REQUEST_ID, ERROR and ERROR_MESSAGE.
auto errorResponse(quint8 type, quint16 request_id, quint8 code, const QByteArray &message)
    -> QByteArray {
    QByteArray bytes("BIPXXX");
    bytes.append(char(0x01));
    bytes.append(char(0xC0 | type));
    bytes.append(char(request_id >> 8));
    bytes.append(char(request_id & 0xFF));
    bytes.append(char(code));
    bytes.append(char(message.size()));
    bytes.append(message);
    return bytes;
}

auto button(QWidget *window, const QString &text) -> catalog::Button * {
    for (auto *candidate : window->findChildren<catalog::Button *>()) {
        if (candidate->text() == text && candidate->isVisible()) {
            return candidate;
        }
    }
    return nullptr;
}

// After a refusal the window shows why with Close alone; closing it answers nothing
// more, as the caller already has the refusal.
void closeRefused(BusSpy &spy, keys::flow::SigningFlow *flow) {
    require(button(flow, QStringLiteral("Close")) != nullptr &&
                button(flow, QStringLiteral("Try Again")) == nullptr,
            "a refused request shows Close, never a retry");
    QPointer<keys::flow::SigningFlow> closed = flow;
    button(flow, QStringLiteral("Close"))->click();
    pump(200);
    require(closed.isNull() && spy.cancelled == 0 && spy.errors == 1,
            "closing a refused request's window answers nothing more");
}

// A QR device refusing the registration, through the window's own decoding of its
// reply: the request's id is the module's first, 1.
void qrRefusal(quint8 code, const QByteArray &message) {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    // The keys store is on disk: the key an earlier case added goes first.
    (void)module->rust()->remove_key(FINGERPRINT, true);
    require(module->rust()->add_key(FINGERPRINT, "QR device").is_ok &&
                module->rust()->add_route(FINGERPRINT, KeyRouteKind::Qr).is_ok,
            "the QR key is added");
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::cancelled, &spy, &BusSpy::onCancelled,
                     qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    module->registerDescriptor(51, QString::fromLatin1(FINGERPRINT), QString::fromLatin1(POLICY));
    auto *flow = waitForFlow();
    require(flow != nullptr, "the registration opens its QR window");
    auto *engine = flow->findChild<qr::QrEngine *>();
    require(engine != nullptr, "the QR window decodes the device's replies");
    // Another request's id is not this request's answer: the scan goes on.
    engine->response({.payload = errorResponse(0x03, 0x0002, code, message)});
    pump(100);
    require(spy.errors == 0 && openFlows().size() == 1,
            "a refusal of another request leaves this one outstanding");
    engine->response({.payload = errorResponse(0x03, 0x0001, code, message)});
    pump(100);
    require(spy.errors == 1 && spy.lastKind == plugin::SignError::DeviceRefused &&
                spy.lastCode == code,
            "a QR device's refusal reaches the caller at once with its code");
    closeRefused(spy, flow);
}

// A USB device the user declines the request on, inside the keys window.
class DecliningSigner final : public ISigner {
public:
    int xpubCalls = 0;

    [[nodiscard]] auto implemented() const -> bool override {
        return true;
    }

    [[nodiscard]] auto id() const -> QString override {
        return QStringLiteral("declining");
    }

    [[nodiscard]] auto fingerprint() const -> QString override {
        return QString::fromLatin1(FINGERPRINT);
    }

    [[nodiscard]] auto walletName() const -> QString override {
        return {};
    }

    [[nodiscard]] auto brand() const -> QString override {
        return QStringLiteral("fixture");
    }

    [[nodiscard]] auto model() const -> QString override {
        return {};
    }

    [[nodiscard]] auto serial() const -> QString override {
        return {};
    }

    [[nodiscard]] auto state() const -> plugin::SignerState override {
        return plugin::SignerState::Ready;
    }

    [[nodiscard]] auto stateDetail() const -> QString override {
        return {};
    }

    [[nodiscard]] auto capabilities() const -> plugin::SignerCapabilities override {
        return {};
    }

    auto init() -> ReqId override {
        return 0;
    }

    auto info() -> ReqId override {
        return 0;
    }

    auto getXpub([[maybe_unused]] const QString &path) -> ReqId override {
        ++xpubCalls;
        return 7;
    }

    auto isDescriptorRegistered([[maybe_unused]] const QString &descriptor) -> ReqId override {
        return 0;
    }

    auto registerDescriptor([[maybe_unused]] const QString &descriptor) -> ReqId override {
        return 0;
    }

    auto signWithDescriptor([[maybe_unused]] const QString &psbt_base64,
                            [[maybe_unused]] const QString &descriptor) -> ReqId override {
        return 0;
    }

    auto displayAddress([[maybe_unused]] const QString &descriptor,
                        [[maybe_unused]] const QString &path,
                        [[maybe_unused]] const QString &address) -> ReqId override {
        return 0;
    }

    auto raw([[maybe_unused]] const QByteArray &request) -> ReqId override {
        return 0;
    }
};

class DeviceInstance final : public QObject, public IInstance {
    Q_OBJECT
    Q_INTERFACES(IInstance)

public:
    DecliningSigner device;

    [[nodiscard]] auto id() const -> QString override {
        return QStringLiteral("declining-device");
    }

    void stop() override {
    }

    auto account() -> IAccount * override {
        return nullptr;
    }

    auto feed() -> IFeed * override {
        return nullptr;
    }

    auto signer() -> ISigner * override {
        return &device;
    }

    auto theme() -> IThemeProvider * override {
        return nullptr;
    }
};

void usbRefusal() {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    // The keys store is on disk: the key an earlier case added goes first.
    (void)module->rust()->remove_key(FINGERPRINT, true);
    require(module->rust()->add_key(FINGERPRINT, "USB device").is_ok &&
                module->rust()->add_route(FINGERPRINT, KeyRouteKind::Usb).is_ok,
            "the USB key is added");
    DeviceInstance instance;
    Host::get()->registerInstance(instance.id(), &instance, module.get());
    pump(50);
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::cancelled, &spy, &BusSpy::onCancelled,
                     qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    module->fetchXpub(52, QString::fromLatin1(FINGERPRINT), QStringLiteral("m/86'/1'/0'"));
    auto *flow = waitForFlow();
    require(flow != nullptr, "the xpub fetch opens the keys window on the USB device");
    pump(100);
    require(instance.device.xpubCalls == 1, "the window asks the device");
    emit instance.device.error(7, QStringLiteral("User refused the request"),
                               plugin::SignError::Other);
    pump(100);
    require(spy.errors == 1 && spy.lastKind == plugin::SignError::DeviceRefused &&
                spy.lastCode == plugin::DEVICE_USER_DECLINED,
            "a USB device the user declined on answers DeviceRefused 0x01 at once");
    closeRefused(spy, flow);
    Host::get()->removeInstance(instance.id(), module.get());
    pump(50);
}

// Reckless's own failures keep their kinds, with no device code.
void ownFailures() {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    module->registerDescriptor(53, QStringLiteral("00000000"), QStringLiteral("not a descriptor"));
    pump(50);
    require(spy.errors == 1 && spy.lastKind == plugin::SignError::Other && spy.lastCode == 0,
            "a registration Reckless cannot make is Other, with no device code");
    module->bus()->sign(54, static_cast<plugin::Network>(99), QString(), {}, QString(), QString());
    pump(50);
    require(spy.errors == 2 && spy.lastKind == plugin::SignError::InvalidRequest &&
                spy.lastCode == 0,
            "an invalid request is InvalidRequest, with no device code");
}

} // namespace

void qrRegistrationSmoke() {
    Theme::get()->apply();
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    (void)module->rust()->remove_key(FINGERPRINT, true);
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

    // ws-plaude/silent#126: a device refusal reaches the caller as DeviceRefused with its
    // bipqr code; Reckless's own failures keep their kinds with no code.
    module->bus()->deliverError(45, QStringLiteral("declined on the device"),
                                plugin::SignError::DeviceRefused, plugin::DEVICE_USER_DECLINED);
    require(spy.errors == 1 && spy.lastKind == plugin::SignError::DeviceRefused &&
                spy.lastCode == 0x01,
            "a device refusal comes with its kind and code");
    module->bus()->deliverError(46, QStringLiteral("lost"), plugin::SignError::MusigSession);
    require(spy.errors == 2 && spy.lastKind == plugin::SignError::MusigSession && spy.lastCode == 0,
            "Reckless's own lost session keeps MusigSession, with no device code");
    require(
        plugin::musigSessionLost(plugin::SignError::DeviceRefused, plugin::DEVICE_MUSIG_SESSION) &&
            plugin::musigSessionLost(plugin::SignError::MusigSession, 0) &&
            !plugin::musigSessionLost(plugin::SignError::DeviceRefused,
                                      plugin::DEVICE_USER_DECLINED) &&
            !plugin::musigSessionLost(plugin::SignError::Other, 0),
        "a device's 0x0D and Reckless's own lost session both restart the attempt");

    qrRefusal(plugin::DEVICE_USER_DECLINED, "registration was declined");
    qrRefusal(0xFF, "device is locked");
    usbRefusal();
    ownFailures();
}

} // namespace smoke

#include "qr_registration_smoke.moc"
