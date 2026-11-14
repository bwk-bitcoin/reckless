#include "account_navigation_smoke.h"

#include "AppController.h"
#include "MainWindow.h"
#include "PluginStopProbe.h"
#include "account/AccountModule.h"
#include "account/AccountShell.h"
#include "host/PluginRegistry.h"
#include "interfaces/host.h"
#include "interfaces/module.h"
#include "modules/multikey/MusigAccountController.h"
#include "modules/multikey/MusigAccountWidget.h"
#include "modules/multikey/MusigStatusBar.h"
#include "modules/sp/AccountController.h"
#include "modules/sp/AccountWidget.h"
#include "modules/sp/StatusBar.h"
#include "theme/Palette.h"
#include "theme/Theme.h"
#include "views/MenuTab.h"

#include <QAbstractButton>
#include <QApplication>
#include <QButtonGroup>
#include <QColor>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QImage>
#include <QMouseEvent>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QThread>
#include <QWidget>
#include <Qontrol>
#include <common.h>
#include <functional>
#include <type_traits>

#if defined(RECKLESS_CUSTOM_WIDGET_FIXTURE) || defined(RECKLESS_CONFIRM_MODAL_FIXTURE) ||          \
    defined(RECKLESS_HOST_WIDGETS_FIXTURE)
#include "PluginBundleFixture.h"
#include <QFile>
#endif
#ifdef RECKLESS_HOST_WIDGETS_FIXTURE
#include "catalog/display/WizardSteps.h"
#include "catalog/feedback/ScanProgress.h"
#include "modules/keys/KeysModule.h"
#include "modules/keys/flow/SigningFlow.h"
#include "qr/QrDisplay.h"
#include <QDir>
#include <QLabel>
#include <QScreen>
#include <QWindow>
#include <memory>
#endif
#ifdef RECKLESS_CONFIRM_MODAL_FIXTURE
#include "catalog/Button.h"
#include "catalog/containers/Modal.h"
#include <QLabel>
#endif

namespace smoke {
namespace {

void require(bool condition, const char *message) {
    if (!condition) {
        qFatal("account navigation: %s", message);
    }
}

void waitFor(const std::function<bool()> &ready) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!ready() && elapsed.elapsed() < 20000) {
        QApplication::processEvents();
        QThread::msleep(1);
    }
    require(ready(), "operation timed out");
    QApplication::processEvents();
}

void click(QAbstractButton *button) {
    auto position = QPointF(button->rect().center());
    auto global = QPointF(button->mapToGlobal(position.toPoint()));
    QMouseEvent press(QEvent::MouseButtonPress, position, global, Qt::LeftButton, Qt::LeftButton,
                      Qt::NoModifier);
    QMouseEvent release(QEvent::MouseButtonRelease, position, global, Qt::LeftButton, Qt::NoButton,
                        Qt::NoModifier);
    QApplication::sendEvent(button, &press);
    QApplication::sendEvent(button, &release);
    QApplication::processEvents();
}

auto menuButton(QButtonGroup &group, const QString &label) -> QAbstractButton * {
    for (auto *button : group.buttons()) {
        if (button->text() == QStringLiteral("  ") + label) {
            return button;
        }
    }
    qFatal("account navigation: missing button %s", qPrintable(label));
}

class StopSpy : public QObject {
public:
    void onStopped() {
        ++count;
    }

    int count = 0;
};

struct Entry {
    QString name;
    QString label;
};

template <typename Widget, typename Status>
void navigation(MainWindow &window, const QString &name, const QList<Entry> &entries) {
    auto *widget = new Widget(name);
    auto *controller = widget->controller();
    // The panels' services come from the account module, for the accounts it watches.
    qobject_cast<account::AccountModule *>(controller->module())
        ->watchAccount(name, controller, controller->services());
    controller->loadPanel(QStringLiteral("settings"));
    window.addTab(widget, name);
    waitFor([controller] {
        return !controller->accountLoading() && !controller->endpointOperationsBusy();
    });
    auto groups = widget->template findChildren<QButtonGroup *>();
    require(groups.size() == 1, "one shared sidebar button group");
    auto *group = groups.first();
    require(group->buttons().size() == entries.size(), "no module placeholder entries");
    require(widget->template findChild<Status *>() != nullptr, "module status retained");
    auto check = [&](const Entry &selected) {
        require(group->checkedButton() == menuButton(*group, selected.label),
                "exact translated label selected");
        int checked = 0;
        for (auto *button : group->buttons()) {
            checked += button->isChecked() ? 1 : 0;
        }
        require(checked == 1, "exactly one checked button");
        for (const auto &entry : entries) {
            auto screen = controller->screen(entry.name);
            require(screen.has_value() &&
                        screen.value()->isVisible() == (entry.name == selected.name),
                    "only selected panel visible");
        }
    };
    check({.name = "settings", .label = "Settings"});
    for (const auto &entry : entries) {
        click(menuButton(*group, entry.label));
        check(entry);
    }
    for (const auto &entry : entries) {
        controller->loadPanel(entry.name);
        check(entry);
        controller->loadPanel(entry.name);
        check(entry);
    }
    controller->loadPanel(QStringLiteral("unknown"));
    check(entries.last());
    controller->loadPanels();
    check(entries.last());
    QList<QPointer<qontrol::Screen>> screens;
    for (const auto &entry : entries) {
        screens.append(controller->screen(entry.name).value());
    }
    QPointer<QObject> backend = controller;
    StopSpy stopped;
    QObject::connect(controller, &std::remove_pointer_t<decltype(controller)>::stopped, &stopped,
                     &StopSpy::onStopped, qontrol::UNIQUE);
    controller->stop();
    waitFor([&stopped] { return stopped.count == 1; });
    window.removeTab(widget);
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(backend == nullptr, "backend destroyed on close");
    for (const auto &screen : screens) {
        require(screen == nullptr, "all panel screens destroyed on close");
    }
}

class EmptyScreen : public qontrol::Screen {
protected:
    void init() override {
    }

    void doConnect() override {
    }

    void view() override {
    }
};

void unavailablePanels() {
    QWidget parent;
    account::AccountShell shell(account::accountMenuEntries(), new QWidget, &parent);
    shell.widget()->show();
    parent.show();
    shell.insertPanel(new qontrol::Panel(new EmptyScreen, "settings"));
    shell.showPanel(QStringLiteral("settings"));
    auto *group = shell.findChild<QButtonGroup *>();
    click(menuButton(*group, QStringLiteral("History")));
    require(group->checkedButton()->text() == QStringLiteral("  Settings"),
            "unavailable clicked panel retains displayed selection");
    shell.showPanel(QStringLiteral("receive"));
    shell.insertPanel(new qontrol::Panel(new EmptyScreen, "unknown"));
    shell.showPanel(QStringLiteral("unknown"));
    require(group->checkedButton()->text() == QStringLiteral("  Settings") &&
                shell.screen(QStringLiteral("settings")).value()->isVisible() &&
                !shell.screen(QStringLiteral("unknown")).value()->isVisible(),
            "missing and unknown panels leave current view unchanged");
    click(menuButton(*group, QStringLiteral("Coins")));
}

// The color of the sidebar's padding, left of the menu buttons.
auto sidebarColor(QWidget *sidebar) -> QColor {
    QCoreApplication::processEvents();
    return sidebar->grab().toImage().pixelColor(1, sidebar->height() / 2);
}

// A theme switch repaints an account page's sidebar in the new theme, not only after a
// restart (#84).
void sidebarFollowsTheme() {
    auto *theme = Theme::get();
    auto initial = theme->mode();
    QWidget parent;
    account::AccountShell shell(account::accountMenuEntries(), new QWidget, &parent);
    parent.resize(1000, 700);
    parent.show();
    QWidget *sidebar = nullptr;
    for (auto *widget : shell.widget()->findChildren<QWidget *>()) {
        if (widget->minimumWidth() == metric::SIDEBAR_WIDTH &&
            widget->maximumWidth() == metric::SIDEBAR_WIDTH) {
            sidebar = widget;
        }
    }
    require(sidebar != nullptr, "the account page has a sidebar");
    theme->setMode(ThemeMode::Dark);
    require(sidebarColor(sidebar) == Palette::dark().bgSecondary,
            "the sidebar takes the dark theme on a switch");
    theme->setMode(ThemeMode::Light);
    require(sidebarColor(sidebar) == Palette::light().bgSecondary,
            "the sidebar takes the light theme on a switch back");
    theme->setMode(initial);
}

#if defined(RECKLESS_CUSTOM_WIDGET_FIXTURE) || defined(RECKLESS_CONFIRM_MODAL_FIXTURE) ||          \
    defined(RECKLESS_HOST_WIDGETS_FIXTURE)
auto fixtureModule(PluginRegistry &registry, const QString &id) -> IModule * {
    for (auto *plugin : registry.plugins()) {
        for (auto *module : plugin->modules()) {
            if (module->meta().value(QStringLiteral("id")) == id) {
                return module;
            }
        }
    }
    return nullptr;
}

auto launcherButton(MenuTab &launcher, const QString &id) -> QPushButton * {
    for (auto *button : launcher.findChildren<QPushButton *>()) {
        if (button->property("instanceId").toString() == id && button->isVisibleTo(&launcher)) {
            return button;
        }
    }
    return nullptr;
}

void openRemainingAccount(MainWindow &window, MenuTab &launcher, PluginRegistry &registry) {
    window.showTab(&launcher);
    launcher.onRefreshLauncherItems();
    QApplication::processEvents();
    auto *button = launcherButton(launcher, QStringLiteral("boundary-sp"));
    require(button != nullptr && button->isEnabled(), "remaining launcher account is available");
    click(button);
    auto *widget = window.findChild<AccountWidget *>();
    require(widget != nullptr, "remaining launcher opens real SP account after plugin unload");
    auto *controller = widget->controller();
    waitFor([controller] {
        return !controller->accountLoading() && !controller->endpointOperationsBusy();
    });
    controller->loadPanel(QStringLiteral("receive"));
    auto *group = widget->findChild<QButtonGroup *>();
    require(group != nullptr && group->checkedButton()->text() == QStringLiteral("  Receive") &&
                controller->screen("receive").value()->isVisible(),
            "remaining account navigation still operates after unload");
    StopSpy stopped;
    QObject::connect(controller, &AccountController::stopped, &stopped, &StopSpy::onStopped,
                     qontrol::UNIQUE);
    Host::get()->removeInstance(QStringLiteral("boundary-sp"),
                                fixtureModule(registry, QStringLiteral("sp.module")));
    waitFor([&stopped] { return stopped.count == 1; });
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(window.findChild<AccountWidget *>() == nullptr, "remaining account closes safely");
}

#endif

#ifdef RECKLESS_CUSTOM_WIDGET_FIXTURE
void customWidget(MainWindow &window) {
    QFile library(QString::fromUtf8(RECKLESS_CUSTOM_WIDGET_FIXTURE));
    require(library.open(QIODevice::ReadOnly), "read external widget fixture");
    require(installBundle(QStringLiteral("custom.widget.fixture"),
                          QStringLiteral("Custom widget fixture"), library.readAll())
                .is_ok,
            "install SDK-only fixture");
    auto *registry = AppController::get()->pluginRegistry();
    rescanPluginsAndWait(registry);
    QPointer<MenuTab> launcher = window.findChild<MenuTab *>();
    require(launcher != nullptr, "real launcher remains alive throughout fixture unload");
    for (int visit = 0; visit < 2; ++visit) {
        require(enablePluginAndWait(registry, QStringLiteral("custom.widget.fixture")),
                "load or re-enable external widget fixture");
        QPointer<IModule> module = fixtureModule(*registry, QStringLiteral("custom.widget.module"));
        require(module != nullptr, "external module is live");
        window.showTab(launcher);
        launcher->onRefreshLauncherItems();
        QApplication::processEvents();
        auto *button = launcherButton(*launcher, QStringLiteral("custom-widget-instance"));
        require(button != nullptr && button->isEnabled(), "launcher lists reloaded fixture");
        click(button);
        auto widgets = window.findChildren<QPushButton *>(QStringLiteral("custom-plugin-widget"));
        require(widgets.size() == 1, "exactly one recreated custom page with no dangling page");
        auto *widget = widgets.first();
        require(widget->isVisible() && widget->text() == QStringLiteral("Independent plugin UI") &&
                    !widget->isChecked(),
                "fresh custom widget published without shell inheritance or panel contract");
        click(widget);
        require(widget->isChecked(), "custom widget handles mouse input");
        QPointer<QWidget> view = widget;
        require(stopPlugin(registry, QStringLiteral("custom.widget.fixture")).isEmpty(),
                "disable and unload fixture while its widget and launcher are alive");
        QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        require(view == nullptr && module == nullptr &&
                    !registry->isPluginEnabled(QStringLiteral("custom.widget.fixture")),
                "live disable destroys page and module");
        require(window.isVisible() && launcher != nullptr,
                "main window and original launcher survive plugin unload");
        window.showTab(launcher);
        launcher->onRefreshLauncherItems();
        require(launcherButton(*launcher, QStringLiteral("custom-widget-instance")) == nullptr &&
                    window.findChild<QPushButton *>(QStringLiteral("custom-plugin-widget")) ==
                        nullptr,
                "unloaded fixture has no stale launcher entry or page");
        openRemainingAccount(window, *launcher, *registry);
    }
}
#endif

#ifdef RECKLESS_HOST_WIDGETS_FIXTURE
// A click as the window system delivers it: through the widget's window, where Qt
// drops it when a modal window blocks that window.
void windowClick(QWidget *widget) {
    auto *window = widget->window()->windowHandle();
    require(window != nullptr, "the clicked widget is on screen");
    const QPointF local = widget->mapTo(widget->window(), QPointF(widget->rect().center()));
    const QPointF global = widget->mapToGlobal(QPointF(widget->rect().center()));
    QMouseEvent press(QEvent::MouseButtonPress, local, local, global, Qt::LeftButton,
                      Qt::LeftButton, Qt::NoModifier);
    QMouseEvent release(QEvent::MouseButtonRelease, local, local, global, Qt::LeftButton,
                        Qt::NoButton, Qt::NoModifier);
    QCoreApplication::sendEvent(window, &press);
    QCoreApplication::sendEvent(window, &release);
    QApplication::processEvents();
}

// The window as the screen shows it, any window over it included.
void shot(MainWindow &window, const QString &name) {
    const auto dir = qEnvironmentVariable("RECKLESS_FIXTURE_SHOTS");
    if (dir.isEmpty()) {
        return;
    }
    QApplication::processEvents();
    const QRect frame = window.frameGeometry();
    auto image =
        window.screen()->grabWindow(0, frame.x(), frame.y(), frame.width(), frame.height());
    require(image.save(QDir(dir).filePath(name)), "the fixture shot saves");
}

// ws-plaude/silent#121: the fixture's tab shows Reckless's own widgets, in the live theme.
// ws-plaude/silent#125: its Count button takes a click while a keys window is open.
void hostWidgetsFixture(MainWindow &window) {
    QFile library(QString::fromUtf8(RECKLESS_HOST_WIDGETS_FIXTURE));
    require(library.open(QIODevice::ReadOnly), "read the host widgets fixture");
    require(installBundle(QStringLiteral("host.widgets.fixture"),
                          QStringLiteral("Host widgets fixture"), library.readAll())
                .is_ok,
            "install the SDK-only host widgets fixture");
    auto *registry = AppController::get()->pluginRegistry();
    rescanPluginsAndWait(registry);
    QPointer<MenuTab> launcher = window.findChild<MenuTab *>();
    require(enablePluginAndWait(registry, QStringLiteral("host.widgets.fixture")),
            "load the host widgets fixture");
    window.showTab(launcher);
    launcher->onRefreshLauncherItems();
    QApplication::processEvents();
    auto *entry = launcherButton(*launcher, QStringLiteral("host-widgets-instance"));
    require(entry != nullptr && entry->isEnabled(), "the launcher lists the fixture");
    click(entry);
    auto *page = window.findChild<QWidget *>(QStringLiteral("host-widgets-page"));
    require(page != nullptr && page->isVisible(), "the fixture's tab is open");
    require(page->findChild<qr::QrDisplay *>() != nullptr &&
                page->findChild<catalog::ScanProgress *>() != nullptr &&
                page->findChild<catalog::WizardSteps *>() != nullptr,
            "the plugin's tab shows Reckless's QR display, scan progress and step trail");
    auto *theme = Theme::get();
    const auto initial = theme->mode();
    for (auto mode : {ThemeMode::Light, ThemeMode::Dark}) {
        theme->setMode(mode);
        theme->apply();
        // The QR display draws its parts and cycles, in the new theme.
        QElapsedTimer settle;
        settle.start();
        while (settle.elapsed() < 1200) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        shot(window, mode == ThemeMode::Light ? QStringLiteral("issue-121-fixture-light.png")
                                              : QStringLiteral("issue-121-fixture-dark.png"));
    }
    theme->setMode(initial);
    theme->apply();

    // A keys window open over the app, as a plugin's keys call opens it.
    auto keys = std::make_unique<keys::KeysModule>();
    keys->setNetwork(Network::Regtest);
    (void)keys->rust()->remove_key("73c5da0a", true);
    require(keys->rust()->add_key("73c5da0a", "QR device").is_ok &&
                keys->rust()->add_route("73c5da0a", KeyRouteKind::Qr).is_ok,
            "the QR key is added");
    keys->checkDescriptorRegistered(
        61, QStringLiteral("73c5da0a"),
        QStringLiteral(
            "tr([73c5da0a/86h/1h/0h]tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWxfTkA6bHNJ3CH"
            "UEtALQdkNeixNz4446PcAmw4WKcj3mV2vb29H7sg9EPzbyCU1y2merw/<0;1>/*)"));
    keys::flow::SigningFlow *flow = nullptr;
    waitFor([&flow] {
        for (auto *widget : QApplication::topLevelWidgets()) {
            if (auto *open = qobject_cast<keys::flow::SigningFlow *>(widget);
                open != nullptr && open->isVisible()) {
                flow = open;
            }
        }
        return flow != nullptr;
    });
    auto *count = window.findChild<QPushButton *>(QStringLiteral("host-widgets-count"));
    auto *clicks = window.findChild<QLabel *>(QStringLiteral("host-widgets-clicks"));
    require(count != nullptr && clicks != nullptr, "the fixture shows its Count button");
    // The check sees a blocking window: made application modal, the click never lands.
    flow->setWindowModality(Qt::ApplicationModal);
    flow->hide();
    flow->show();
    flow->move(window.x() + window.width() - flow->width() - 24, window.y() + 120);
    QApplication::processEvents();
    windowClick(count);
    windowClick(count);
    require(clicks->text() == QStringLiteral("0"),
            "a modal keys window blocks the plugin's tab: the check would see the bug");
    shot(window, QStringLiteral("issue-125-fixture-modal-blocked.png"));
    flow->hide();
    flow->setWindowModality(Qt::NonModal);
    flow->show();
    // Beside the Count button, so the shot shows both.
    flow->move(window.x() + window.width() - flow->width() - 24, window.y() + 120);
    QApplication::processEvents();
    windowClick(count);
    windowClick(count);
    require(flow->isVisible() && clicks->text() == QStringLiteral("2"),
            "the plugin's button takes clicks while the keys window is open");
    shot(window, QStringLiteral("issue-125-fixture-click.png"));
    QPointer<keys::flow::SigningFlow> closed = flow;
    flow->reject();
    QApplication::processEvents();
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(closed.isNull(), "the keys window closes");
    keys.reset();

    QPointer<QWidget> view = page;
    require(stopPlugin(registry, QStringLiteral("host.widgets.fixture")).isEmpty(),
            "disable the host widgets fixture");
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(view.isNull(), "the fixture's tab goes with it");
}
#endif

#ifdef RECKLESS_CONFIRM_MODAL_FIXTURE
// ws-plaude/silent#127: the fixture's Reset asks for Reckless's confirmation modal.
auto openConfirmModal(MainWindow &window) -> QPointer<catalog::Modal> {
    auto *reset = window.findChild<QPushButton *>(QStringLiteral("confirm-plugin-reset"));
    require(reset != nullptr && reset->isVisible(), "the fixture's tab shows its Reset button");
    click(reset);
    QPointer<catalog::Modal> modal;
    waitFor([&window, &modal] {
        for (auto *candidate : window.findChildren<catalog::Modal *>()) {
            if (candidate->isVisible()) {
                modal = candidate;
            }
        }
        return modal != nullptr;
    });
    require(modal->parentWidget() == &window && modal->windowModality() == Qt::WindowModal,
            "the plugin's confirmation opens window-modal over the main window");
    require(modal->windowTitle() == QStringLiteral("Reset all results"),
            "the plugin's confirmation carries its title");
    return modal;
}

auto modalButton(catalog::Modal *modal, const QString &text) -> catalog::Button * {
    for (auto *candidate : modal->findChildren<catalog::Button *>()) {
        if (candidate->text() == text && candidate->isVisible()) {
            return candidate;
        }
    }
    qFatal("account navigation: no %s button in the confirmation", qPrintable(text));
}

void confirmModalFixture(MainWindow &window) {
    QFile library(QString::fromUtf8(RECKLESS_CONFIRM_MODAL_FIXTURE));
    require(library.open(QIODevice::ReadOnly), "read the confirm modal fixture");
    require(installBundle(QStringLiteral("confirm.modal.fixture"),
                          QStringLiteral("Confirm modal fixture"), library.readAll())
                .is_ok,
            "install the SDK-only confirm modal fixture");
    auto *registry = AppController::get()->pluginRegistry();
    rescanPluginsAndWait(registry);
    QPointer<MenuTab> launcher = window.findChild<MenuTab *>();
    require(enablePluginAndWait(registry, QStringLiteral("confirm.modal.fixture")),
            "load the confirm modal fixture");
    window.showTab(launcher);
    launcher->onRefreshLauncherItems();
    QApplication::processEvents();
    auto *entry = launcherButton(*launcher, QStringLiteral("confirm-modal-instance"));
    require(entry != nullptr && entry->isEnabled(), "the launcher lists the fixture");
    click(entry);
    QPointer<QLabel> answer = window.findChild<QLabel *>(QStringLiteral("confirm-plugin-answer"));
    require(answer != nullptr, "the fixture's tab is open");

#ifdef RECKLESS_HOST_WIDGETS_FIXTURE
    // Shots of the plugin's confirmation, light and dark.
    const auto initial_mode = Theme::get()->mode();
    for (auto mode : {ThemeMode::Light, ThemeMode::Dark}) {
        Theme::get()->setMode(mode);
        Theme::get()->apply();
        QApplication::processEvents();
        auto open = openConfirmModal(window);
        QElapsedTimer settle;
        settle.start();
        while (settle.elapsed() < 500) {
            QApplication::processEvents(QEventLoop::AllEvents, 20);
        }
        shot(window, mode == ThemeMode::Light ? QStringLiteral("issue-127-confirm-light.png")
                                              : QStringLiteral("issue-127-confirm-dark.png"));
        click(modalButton(open, QStringLiteral("Cancel")));
        waitFor([&answer] { return answer->text() == QStringLiteral("cancelled"); });
        answer->clear();
        QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    Theme::get()->setMode(initial_mode);
    Theme::get()->apply();
#endif
    auto modal = openConfirmModal(window);
    click(modalButton(modal, QStringLiteral("Reset all results")));
    waitFor([&answer] { return answer->text() == QStringLiteral("confirmed"); });
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(modal.isNull(), "the confirmed modal is gone");

    modal = openConfirmModal(window);
    click(modalButton(modal, QStringLiteral("Cancel")));
    waitFor([&answer] { return answer->text() == QStringLiteral("cancelled"); });
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(modal.isNull(), "the cancelled modal is gone");

    // Disabled while its confirmation is open: the modal closes with the plugin's tab,
    // keeping its own copy of the plugin's text once the library is unloaded.
    modal = openConfirmModal(window);
    answer->clear();
    require(stopPlugin(registry, QStringLiteral("confirm.modal.fixture")).isEmpty(),
            "disable the fixture while its confirmation is open");
    QApplication::processEvents();
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    require(modal.isNull() && answer.isNull(),
            "the confirmation closes with the plugin's tab, without answering it");
    require(window.isVisible(), "the main window survives the plugin and its modal");
}
#endif

} // namespace

void accountNavigationSmoke() {
    {
        MainWindow window;
        AppController::get()->start(&window);
        window.resize(1440, 1000);
        window.show();
        QList<Entry> sp{{.name = "history", .label = "History"},
                        {.name = "coins", .label = "Coins"},
                        {.name = "send", .label = "Send"},
                        {.name = "receive", .label = "Receive"},
                        {.name = "settings", .label = "Settings"}};
        auto musig = sp;
        musig.insert(musig.size() - 1, {.name = "psbt", .label = "PSBT"});
        for (int repeat = 0; repeat < 2; ++repeat) {
            navigation<AccountWidget, StatusBar>(window, QStringLiteral("boundary-sp"), sp);
            navigation<MusigAccountWidget, MusigStatusBar>(
                window, QStringLiteral("boundary-policy"), musig);
        }
        unavailablePanels();
#ifdef RECKLESS_HOST_WIDGETS_FIXTURE
        hostWidgetsFixture(window);
#endif
#ifdef RECKLESS_CONFIRM_MODAL_FIXTURE
        confirmModalFixture(window);
#endif
#ifdef RECKLESS_CUSTOM_WIDGET_FIXTURE
        customWidget(window);
        navigation<AccountWidget, StatusBar>(window, QStringLiteral("boundary-sp"), sp);
        navigation<MusigAccountWidget, MusigStatusBar>(window, QStringLiteral("boundary-policy"),
                                                       musig);
#endif
    }
    // After the main window: a theme switch restyles every widget of the app.
    sidebarFollowsTheme();
    AppController::get()->start(nullptr);
}

} // namespace smoke
