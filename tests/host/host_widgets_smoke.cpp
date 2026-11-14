// ws-plaude/silent#121: the host gives plugins Reckless's QR display, scan progress and
// step trail through the plugin interface (interfaces/widgets.h), made by Host and
// drawn in the live theme.
#include "catalog/display/WizardSteps.h"
#include "catalog/feedback/ScanProgress.h"
#include "interfaces/host.h"
#include "interfaces/widgets.h"
#include "qr/QrDisplay.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QPointer>
#include <QRegularExpression>
#include <QThread>
#include <QWidget>

#include <algorithm>
#include <memory>

namespace smoke {
namespace {

void require(bool condition, const char *message) {
    if (!condition) {
        qFatal("host widgets smoke: %s", message);
    }
}

void pump(int ms) {
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < ms) {
        QApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(5);
    }
}

auto hasLabel(QWidget *widget, const QString &text) -> bool {
    auto labels = widget->findChildren<QLabel *>();
    return std::ranges::any_of(labels,
                               [&text](const QLabel *label) { return label->text() == text; });
}

auto dots(QWidget *widget) -> int {
    int count = 0;
    for (auto *label : widget->findChildren<QLabel *>()) {
        count += label->property("class").toString() == QStringLiteral("wizard-dot") ? 1 : 0;
    }
    return count;
}

} // namespace

void hostWidgetsSmoke() {
    for (auto mode : {ThemeMode::Light, ThemeMode::Dark}) {
        Theme::get()->setMode(mode);
        Theme::get()->apply();
        auto page = std::make_unique<QWidget>();
        auto *host = Host::get();

        // The QR display: Reckless's QrDisplay, cycling the payload's BBQR parts.
        QPointer<IQrDisplayWidget> display = host->createQrDisplay(page.get());
        require(display != nullptr && display->parent() == page.get(),
                "the QR display is made as a child of the plugin's widget");
        require(display->findChild<qr::QrDisplay *>() != nullptr,
                "the QR display is Reckless's own");
        display->setCodeSize(240);
        display->setPayload(QByteArray(1200, 'x'));
        page->show();
        pump(1500);
        static const QRegularExpression part(QStringLiteral("^Part \\d+ / \\d+$"));
        auto labels = display->findChildren<QLabel *>();
        require(std::ranges::any_of(labels,
                                    [](const QLabel *label) {
                                        return part.match(label->text()).hasMatch();
                                    }),
                "a multi-part payload shows Reckless's part count");
        display->stop();

        // The scan progress: Reckless's ScanProgress and its caption.
        auto *progress = host->createScanProgress(page.get());
        require(progress->findChild<catalog::ScanProgress *>() != nullptr,
                "the scan progress is Reckless's own");
        progress->setProgress(0, 0);
        require(hasLabel(progress, QStringLiteral("Waiting for the first part…")),
                "nothing received yet waits for the first part");
        progress->setProgress(2, 5);
        require(hasLabel(progress, QStringLiteral("2 of 5 parts")), "the parts are counted");

        // The step trail: Reckless's WizardSteps, growing while the flow runs.
        auto *trail = host->createStepTrail(page.get());
        trail->setSteps({QStringLiteral("Device"), QStringLiteral("Wallet")});
        trail->setCurrent(1);
        pump(50);
        require(trail->findChild<catalog::WizardSteps *>() != nullptr && dots(trail) == 2,
                "the trail shows its two named steps");
        trail->setSteps(
            {QStringLiteral("Device"), QStringLiteral("Wallet"), QStringLiteral("Check")});
        pump(50);
        require(dots(trail) == 3 && hasLabel(trail, QStringLiteral("Check")),
                "a longer list grows the trail");
        trail->setStepCount(4);
        pump(50);
        require(dots(trail) == 4, "a count without names numbers its steps");

        page.reset();
        require(display.isNull(), "the plugin's widget owns what the host made for it");
    }
}

} // namespace smoke
