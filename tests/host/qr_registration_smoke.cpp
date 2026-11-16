// ws-plaude/silent#114: registerDescriptor on a QR key shows the Descriptor
// Registration request in the key's QR window, and answers only with the device's
// answer: closing the window answers cancelled, never registered.
// ws-plaude/silent#125: the window does not block the rest of the app, one at a time.
// ws-plaude/silent#115: checkDescriptorRegistered on a QR key shows the registration
// check there too, never a "disconnected" error about a device that has no connection.
// ws-plaude/silent#126: a device's refusal, over QR codes or USB, reaches the caller
// through the keys window as DeviceRefused with the device's own code.
// ws-plaude/silent#134: the caller of a keys call gets each bipqr request shown and
// each reply read, refused ones included; no other caller does.
// ws-plaude/silent#135: on the MuSig2 QR routes, a device's own refusal reaches the
// caller as DeviceRefused with its code, its 0x0D included.
// ws-plaude/silent#130: unregisterDescriptor on a QR key asks the device to forget the
// wallet in the keys QR window; its ok and its 0x04 clear the registration record.
#include "AppController.h"
#include "MockPlugin.h"
#include "catalog/Button.h"
#include "host/CallerHandles.h"
#include "host/Host.h"
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
#include <QLabel>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QString>
#include <algorithm>
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
    int unregistered = 0;
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

    void onUnregistered([[maybe_unused]] ReqId req_id,
                        [[maybe_unused]] const QString &fingerprint) {
        ++unregistered;
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

// A registered built-in module, the callers' as a plugin's would be.
auto callerModule() -> IModule * {
    static IModule *module = nullptr;
    if (module == nullptr) {
        if (AppController::get() == nullptr) {
            AppController::init();
        }
        auto plugin = std::make_unique<MockPlugin>();
        module = plugin->module();
        AppController::get()->registerBuiltinPlugin(std::move(plugin));
    }
    return module;
}

// The bipqr exchanges a keys caller receives.
class ExchangeSpy final : public QObject {
    Q_OBJECT

public:
    QList<ReqId> ids;
    QList<plugin::KeyExchange> seen;

public slots:

    void onExchange(ReqId req_id, const plugin::KeyExchange &exchange) {
        ids.append(req_id);
        seen.append(exchange);
    }
};

// A registration through a caller's handle, the device answering with bipqr's
// register_descriptor_response_registered vector, or refusing it: the caller gets the
// request, a reply for another request (refused) and the device's reply, in order.
void qrExchanges(bool device_refuses) {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    (void)module->rust()->remove_key(FINGERPRINT, true);
    require(module->rust()->add_key(FINGERPRINT, "QR device").is_ok &&
                module->rust()->add_route(FINGERPRINT, KeyRouteKind::Qr).is_ok,
            "the QR key is added");
    auto *host = dynamic_cast<HostImpl *>(Host::get());
    require(host != nullptr, "the real host");
    host::KeysHandle caller(host, callerModule(), module->bus());
    host::KeysHandle other(host, callerModule(), module->bus());
    ExchangeSpy mine;
    ExchangeSpy theirs;
    QObject::connect(&caller, &IKeys::exchange, &mine, &ExchangeSpy::onExchange, qontrol::UNIQUE);
    QObject::connect(&other, &IKeys::exchange, &theirs, &ExchangeSpy::onExchange, qontrol::UNIQUE);
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::descriptorRegistered, &spy,
                     &BusSpy::onRegistered, qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    auto req = caller.newRequest();
    caller.registerDescriptor(req, plugin::Network::Regtest, QString::fromLatin1(FINGERPRINT),
                              QString::fromLatin1(POLICY));
    auto *flow = waitForFlow();
    require(flow != nullptr, "the registration opens its QR window");
    auto *engine = flow->findChild<qr::QrEngine *>();
    require(engine != nullptr, "the QR window decodes the device's replies");
    pump(50);
    require(mine.seen.size() == 1, "the caller gets the request shown");
    const auto &shown = mine.seen.at(0);
    require(shown.direction == plugin::ExchangeDirection::Request &&
                shown.route == plugin::KeyRouteKind::Qr && shown.accepted &&
                shown.bytes.startsWith("BIPXXX") && shown.bytes.size() > 10 &&
                static_cast<quint8>(shown.bytes.at(7)) == 0x03 &&
                shown.bytes.mid(8, 2) == QByteArray("\x00\x01", 2),
            "the request is the whole bipqr Register Descriptor message, REQUEST_ID 1");

    const auto answer =
        device_refuses
            ? errorResponse(0x03, 0x0001, plugin::DEVICE_USER_DECLINED, "registration was declined")
            : QByteArray::fromHex("42495058585801830001046d61696e0101010108aaaaaaaaaaaaaaaa");
    auto stray = answer;
    stray[9] = 0x02;
    engine->response({.payload = stray});
    pump(100);
    require(mine.seen.size() == 2 &&
                mine.seen.at(1).direction == plugin::ExchangeDirection::Reply &&
                mine.seen.at(1).bytes == stray && !mine.seen.at(1).accepted &&
                !mine.seen.at(1).note.isEmpty(),
            "a reply to another request comes as refused, with why");
    engine->response({.payload = answer});
    pump(200);
    require(mine.seen.size() == 3 &&
                mine.seen.at(2).direction == plugin::ExchangeDirection::Reply &&
                mine.seen.at(2).bytes == answer && mine.seen.at(2).accepted,
            "the device's reply comes as read, a refusal as much as an answer");
    require(device_refuses ? spy.errors == 1 && spy.lastCode == plugin::DEVICE_USER_DECLINED
                           : spy.registered == 1,
            "the call answers as before");
    require(std::ranges::all_of(mine.ids, [req](ReqId id) { return id == req; }),
            "every exchange carries the caller's request id");
    require(theirs.seen.isEmpty(), "another caller gets none of them");
    if (!device_refuses) {
        return;
    }
    // The refused window waits for Close.
    if (auto *open = waitForFlow(); open != nullptr) {
        open->reject();
        pump(200);
    }
}

// A funded attempt of POLICY spending one MuSig2 input, as reckless/tests/keys_qr_cache.rs
// builds it (FundedAttempt): its PSBT v2, for the signing plan of the MuSig2 routes.
const char *const MUSIG_ATTEMPT_PSBT =
    "70736274ff010204020000000103040000000001040101010501020106010001fb040200000019fc16524543"
    "4b4c4553535f4d555349475f415454454d50540020a2083e66371469b91844a18d4d649af739dfb9e4ab5596"
    "aa3b1bbe0a8142963b0001012ba086010000000000225120b18e7f13c7db58ca6f755ccd7541149a4e7edda1"
    "f041013256641845a4cc9b64010e204941a4208eb4762c85643079a865a08efbfecef62fd2fc78bc0184b8b8"
    "cb0d2a010f040000000001100400000000211608c426b56c36540026267f37e3ca01126ac96da1e2c704836a"
    "76a7b78dc935901100b8688df157000080010000800000008021164fa60842fe43fd476291703aa69974a232"
    "2e835f37c6acd4f22d4b152f15039b110073c5da0a5700008001000080000000802116f3b2fc338d232bb46b"
    "e409bda6356529592783a0a8a2b86ce4da3ce2a87978c70d002e36efc30000000001000000011720f3b2fc33"
    "8d232bb46be409bda6356529592783a0a8a2b86ce4da3ce2a87978c7221a021e4240bacca55cb106a7546000"
    "c79549350df61064a51d2d6154f57bec0d75fb420208c426b56c36540026267f37e3ca01126ac96da1e2c704"
    "836a76a7b78dc93590024fa60842fe43fd476291703aa69974a2322e835f37c6acd4f22d4b152f15039b0001"
    "030878e6000000000000010422512015c21d32164c3c90f423cd5ff5db0f17f59a999d40b67bcca892e4f7cb"
    "2424140105204080b32bf5b80bbe6ddc54488bf5f28306c8dad596dfeedf0d11707e617b1ffa210708c426b5"
    "6c36540026267f37e3ca01126ac96da1e2c704836a76a7b78dc935901100b8688df157000080010000800000"
    "008021074080b32bf5b80bbe6ddc54488bf5f28306c8dad596dfeedf0d11707e617b1ffa0d002e36efc30100"
    "00000100000021074fa60842fe43fd476291703aa69974a2322e835f37c6acd4f22d4b152f15039b110073c5"
    "da0a5700008001000080000000802208021e4240bacca55cb106a7546000c79549350df61064a51d2d6154f5"
    "7bec0d75fb420208c426b56c36540026267f37e3ca01126ac96da1e2c704836a76a7b78dc93590024fa60842"
    "fe43fd476291703aa69974a2322e835f37c6acd4f22d4b152f15039b00010308409c00000000000001042251"
    "204121b67d9fa26ed1eed5264219c418e35b7f663010b44813328e8d462548c0b000";

// The request shown last, among the call's exchanges (ws-plaude/silent#134).
auto lastRequest(const QList<plugin::KeyExchange> &seen) -> QByteArray {
    for (auto it = seen.crbegin(); it != seen.crend(); ++it) {
        if (it->direction == plugin::ExchangeDirection::Request) {
            return it->bytes;
        }
    }
    return {};
}

// A MuSig2 call on a QR key, through IKeys, refused by its device with `code`: on the
// nonce cache route (`cache`, the key's device advertising the cache bit, a nonce
// preparation) or on round 1 of the two-round signing.
void qrMusigRefusal(bool cache, quint8 code) {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    (void)module->rust()->remove_key(FINGERPRINT, true);
    require(module->rust()->add_key(FINGERPRINT, "QR device").is_ok &&
                module->rust()->add_route(FINGERPRINT, KeyRouteKind::Qr).is_ok &&
                module->rust()->register_descriptor(FINGERPRINT, POLICY).is_ok,
            "the QR key holds the MuSig2 wallet");
    if (cache) {
        auto recorded = module->rust()->record_device(LiveDevice{
            .device_id = "qr-device",
            .fingerprint = FINGERPRINT,
            .kind = "qr",
            .brand = "fixture",
            .model = "",
            .serial = "",
            .module = "qr",
            .version = "1.0",
            .capabilities = (1U << 0) | (1U << 1) | (1U << 3) | (1U << 4),
        });
        require(recorded.is_ok, "the key's QR device advertises the nonce cache");
    }
    auto *host = dynamic_cast<HostImpl *>(Host::get());
    require(host != nullptr, "the real host");
    host::KeysHandle caller(host, callerModule(), module->bus());
    ExchangeSpy exchanges;
    QObject::connect(&caller, &IKeys::exchange, &exchanges, &ExchangeSpy::onExchange,
                     qontrol::UNIQUE);
    BusSpy spy;
    QObject::connect(&caller, &IKeys::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    auto req = caller.newRequest();
    const auto psbt = QString::fromLatin1(MUSIG_ATTEMPT_PSBT);
    if (cache) {
        caller.prepareNonces(req, plugin::Network::Regtest, psbt, QString::fromLatin1(POLICY),
                             QString::fromLatin1(FINGERPRINT));
    } else {
        caller.sign(req, plugin::Network::Regtest, psbt, {QString::fromLatin1(POLICY)}, QString(),
                    QString::fromLatin1(FINGERPRINT));
    }
    auto *flow = waitForFlow();
    require(flow != nullptr, "the MuSig2 call opens the key's QR window");
    // The window starts its route once it is shown.
    pump(200);
    auto *engine = flow->findChild<qr::QrEngine *>();
    require(engine != nullptr, "the QR window decodes the device's replies");
    QElapsedTimer shown;
    shown.start();
    while (lastRequest(exchanges.seen).isEmpty() && shown.elapsed() < 10000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    const auto request = lastRequest(exchanges.seen);
    require(request.size() > 10, "the window shows its bipqr request");
    const auto type = static_cast<quint8>(request.at(7)) & 0x3F;
    require(cache ? type == 0x06 : type == 0x05,
            "a nonce preparation on the cache route, a Signing request on round 1");
    const auto id = static_cast<quint16>((static_cast<quint8>(request.at(8)) << 8) |
                                         static_cast<quint8>(request.at(9)));
    engine->response({.payload = errorResponse(type, id, code, "refused by the device")});
    QElapsedTimer answered;
    answered.start();
    while (spy.errors == 0 && answered.elapsed() < 10000) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    require(spy.errors == 1 && spy.lastKind == plugin::SignError::DeviceRefused &&
                spy.lastCode == code,
            "the caller gets the device's refusal as DeviceRefused with its code");
    for (auto *open : openFlows()) {
        open->reject();
    }
    pump(200);
}

// Whether a request to the key now carries the wallet's descriptor body: false while its
// device is recorded as keeping the wallet, true once that record is cleared.
auto carriesDescriptor(keys::KeysModule &module) -> bool {
    auto request = module.rust()->qr_request_verify_address(FINGERPRINT, POLICY, "m/0/0", "bcrt1q");
    require(request.is_ok, "a verify request to the key");
    QByteArray bytes(reinterpret_cast<const char *>(request.payload.data()),
                     static_cast<qsizetype>(request.payload.size()));
    return bytes.contains("tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWxfTkA6bHNJ3CH");
}

// The device answers the unregistration with `code` (0: bipqr's
// unregister_descriptor_response vector, an ok).
void qrUnregistration(quint8 code) {
    auto module = std::make_unique<keys::KeysModule>();
    module->setNetwork(Network::Regtest);
    (void)module->rust()->remove_key(FINGERPRINT, true);
    require(module->rust()->add_key(FINGERPRINT, "QR device").is_ok &&
                module->rust()->add_route(FINGERPRINT, KeyRouteKind::Qr).is_ok &&
                module->rust()->set_descriptor_registration(FINGERPRINT, POLICY, true, "").is_ok,
            "the QR key holds the wallet, its device recorded as keeping it");
    require(!carriesDescriptor(*module), "a request names the kept wallet by its alias alone");
    BusSpy spy;
    QObject::connect(module->bus(), &keys::KeysBus::error, &spy, &BusSpy::onError, qontrol::UNIQUE);
    QObject::connect(module->bus(), &keys::KeysBus::descriptorUnregistered, &spy,
                     &BusSpy::onUnregistered, qontrol::UNIQUE);
    module->unregisterDescriptor(81, QString::fromLatin1(FINGERPRINT), QString::fromLatin1(POLICY));
    auto *flow = waitForFlow();
    require(flow != nullptr && flow->windowTitle() == QStringLiteral("Show Unregistration Request"),
            "the unregistration shows its request in the QR window");
    auto *engine = flow->findChild<qr::QrEngine *>();
    require(engine != nullptr, "the QR window decodes the device's replies");
    // The verify request above took REQUEST_ID 1: the unregistration's is 2.
    auto answer = code == 0
                      ? QByteArray::fromHex("42495058585801870001046d61696e")
                      : errorResponse(0x07, 0x0002, code, "the device refused the unregistration");
    answer[9] = 0x02;
    engine->response({.payload = answer});
    pump(200);
    if (code == 0) {
        require(spy.unregistered == 1 && spy.errors == 0, "the device's ok answers unregistered");
    } else {
        require(spy.errors == 1 && spy.lastKind == plugin::SignError::DeviceRefused &&
                    spy.lastCode == code,
                "a refusal reaches the caller with its code");
        require(button(flow, QStringLiteral("Close")) != nullptr,
                "the refusal shows its reason with Close");
        bool explained = false;
        for (auto *label : flow->findChildren<QLabel *>()) {
            explained |= code == plugin::DEVICE_ALIAS_UNKNOWN &&
                         label->text().startsWith(QStringLiteral("The device no longer holds"));
            explained |= code == plugin::DEVICE_UNSUPPORTED_OPERATION &&
                         label->text().startsWith(QStringLiteral("This device keeps no wallet"));
            explained |= code == plugin::DEVICE_USER_DECLINED;
        }
        require(explained, "0x04 and 0x0F say what they mean for the wallet");
        button(flow, QStringLiteral("Close"))->click();
        pump(200);
    }
    const bool cleared = code == 0 || code == plugin::DEVICE_ALIAS_UNKNOWN;
    require(carriesDescriptor(*module) == cleared,
            "an ok or 0x04 clears the record, so requests carry the wallet again; 0x01 and "
            "0x0F keep it");
    require(openFlows().isEmpty(), "the window is closed");
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
    qrExchanges(false);
    qrExchanges(true);
    for (quint8 code : {quint8(0), plugin::DEVICE_ALIAS_UNKNOWN, plugin::DEVICE_USER_DECLINED,
                        plugin::DEVICE_UNSUPPORTED_OPERATION}) {
        qrUnregistration(code);
    }
    for (bool cache : {true, false}) {
        for (quint8 code : {plugin::DEVICE_MUSIG_SESSION, plugin::DEVICE_USER_DECLINED}) {
            qrMusigRefusal(cache, code);
        }
    }
}

} // namespace smoke

#include "qr_registration_smoke.moc"
