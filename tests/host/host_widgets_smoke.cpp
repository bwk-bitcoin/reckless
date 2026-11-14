// ws-plaude/silent#121: the host gives plugins Reckless's QR display, scan progress and
// step trail through the plugin interface (interfaces/widgets.h), made by Host and
// drawn in the live theme; #127 its confirmation modal (Host::createConfirmModal).
#include "catalog/Button.h"
#include "catalog/containers/Modal.h"
#include "catalog/display/WizardSteps.h"
#include "catalog/feedback/ScanProgress.h"
#include "interfaces/host.h"
#include "interfaces/widgets.h"
#include "qr/QrDisplay.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QDialog>
#include <QElapsedTimer>
#include <QKeyEvent>
#include <QLabel>
#include <QObject>
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

// What a plugin hears back from a confirmation modal.
class ConfirmProbe : public QObject {
    Q_OBJECT

public:
    int confirmed = 0;
    int cancelled = 0;

public slots:

    void onAccepted() {
        ++confirmed;
    }

    void onRejected() {
        ++cancelled;
    }
};

auto button(QDialog *modal, const QString &text) -> catalog::Button * {
    for (auto *candidate : modal->findChildren<catalog::Button *>()) {
        if (candidate->text() == text && candidate->isVisible()) {
            return candidate;
        }
    }
    return nullptr;
}

// Opens a confirmation over `page` as a plugin does and checks it is Reckless's.
auto openConfirm(QWidget *page, ConfirmProbe &probe, bool destructive) -> QPointer<QDialog> {
    QPointer<QDialog> modal = Host::get()->createConfirmModal(
        page, {.title = QStringLiteral("Reset all results"),
               .message = QStringLiteral("Every saved result of the conformance run is deleted.\n"
                                         "<b>This cannot be undone.</b>"),
               .confirmLabel = QStringLiteral("Reset all results"),
               .destructive = destructive});
    require(modal != nullptr, "the host makes a confirmation modal");
    QObject::connect(modal, &QDialog::accepted, &probe, &ConfirmProbe::onAccepted);
    QObject::connect(modal, &QDialog::rejected, &probe, &ConfirmProbe::onRejected);
    modal->open();
    pump(100);
    require(modal->isVisible() && modal->parentWidget() == page->window() &&
                modal->windowModality() == Qt::WindowModal,
            "the modal opens window-modal over the plugin's window");
    require(qobject_cast<catalog::Modal *>(modal.data()) != nullptr,
            "the confirmation is Reckless's own catalog::Modal");
    require(modal->windowTitle() == QStringLiteral("Reset all results"),
            "the plugin's title is the modal's");
    auto labels = modal->findChildren<QLabel *>();
    require(std::ranges::any_of(labels,
                                [](const QLabel *label) {
                                    return label->textFormat() == Qt::PlainText &&
                                           label->text().contains(QStringLiteral("<b>"));
                                }),
            "the message shows as plain text, never as rich text");
    auto *cancel = button(modal, QStringLiteral("Cancel"));
    auto *confirm = button(modal, QStringLiteral("Reset all results"));
    require(cancel != nullptr && confirm != nullptr, "Cancel and the plugin's button show");
    require(confirm->role() ==
                (destructive ? catalog::ButtonRole::Destructive : catalog::ButtonRole::Primary),
            "a destructive confirmation has the red button, else the accent one");
    require(cancel->mapTo(modal, QPoint()).x() < confirm->mapTo(modal, QPoint()).x(),
            "Cancel sits before the confirm button, as in DisablePlugin");
    return modal;
}

void confirmModal() {
    auto page = std::make_unique<QWidget>();
    page->resize(800, 600);
    page->show();
    pump(50);
    // Confirm: accepted, once, and the modal is gone.
    {
        ConfirmProbe probe;
        auto modal = openConfirm(page.get(), probe, true);
        button(modal, QStringLiteral("Reset all results"))->click();
        pump(50);
        require(probe.confirmed == 1 && probe.cancelled == 0, "confirming answers confirmed");
        require(modal.isNull(), "a closed confirmation deletes itself");
    }
    // Cancel, Escape and the titlebar's close each answer cancelled.
    for (int way = 0; way < 3; ++way) {
        ConfirmProbe probe;
        auto modal = openConfirm(page.get(), probe, way == 1);
        if (way == 0) {
            button(modal, QStringLiteral("Cancel"))->click();
        } else if (way == 1) {
            QKeyEvent escape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
            QApplication::sendEvent(modal, &escape);
        } else {
            modal->close();
        }
        pump(50);
        require(probe.confirmed == 0 && probe.cancelled == 1,
                "Cancel, Escape and closing the window answer cancelled");
        require(modal.isNull(), "a cancelled confirmation deletes itself");
    }
    // The answer is also the dialog's result, what exec() returns.
    {
        QPointer<QDialog> modal =
            Host::get()->createConfirmModal(page.get(), {.title = QStringLiteral("Forget"),
                                                         .message = QStringLiteral("Forget it?"),
                                                         .confirmLabel = QStringLiteral("Forget")});
        modal->open();
        pump(50);
        button(modal, QStringLiteral("Forget"))->click();
        require(modal->result() == QDialog::Accepted, "a confirmed modal's result is Accepted");
        pump(50);
        require(modal.isNull(), "a confirmed modal deletes itself");
    }
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
        // ws-plaude/silent#133: a step's state stays through a longer list.
        trail->setStepState(1, plugin::StepState::Failed);
        trail->setSteps({QStringLiteral("Device"), QStringLiteral("Wallet"),
                         QStringLiteral("Check"), QStringLiteral("Done")});
        pump(50);
        require(trail->findChild<catalog::WizardSteps *>()->stepState(1) ==
                    plugin::StepState::Failed,
                "a step's state is kept when the plugin grows the list");
        trail->setStepCount(4);
        pump(50);
        require(dots(trail) == 4, "a count without names numbers its steps");

        page.reset();
        require(display.isNull(), "the plugin's widget owns what the host made for it");

        confirmModal();
    }
}

} // namespace smoke

#include "host_widgets_smoke.moc"
