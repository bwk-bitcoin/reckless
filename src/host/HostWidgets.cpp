#include "HostWidgets.h"

#include "catalog/Button.h"
#include "catalog/Variants.h"
#include "catalog/containers/ModalActions.h"
#include "catalog/display/Label.h"
#include "catalog/display/WizardSteps.h"
#include "catalog/feedback/ScanProgress.h"
#include "i18n/Tr.h"
#include "modules/keys/flow/QrSettings.h"
#include "qr/QrDisplay.h"
#include "qr/QrTypes.h"
#include "qr/bbqr/BbqrDisplayEngine.h"
#include "theme/Palette.h"

#include <QEvent>
#include <QVBoxLayout>
#include <Qontrol>
#include <algorithm>
#include <common.h>
#include <utility>

namespace {

// A bare column holding the one wrapped widget, centred.
auto column(QWidget *owner) -> QVBoxLayout * {
    auto *layout = new QVBoxLayout(owner);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    return layout;
}

} // namespace

// ===== QR display =====

HostQrDisplay::HostQrDisplay(QWidget *parent) : IQrDisplayWidget(parent) {
    m_display = new qr::QrDisplay(this);
    m_engine = new qr::BbqrDisplayEngine(this);
    // The tuning the user picked in Reckless, as for its own QR codes.
    keys::flow::applyQrLevels(m_engine);
    connect(m_engine, &qr::QrDisplayEngine::frame, m_display, &qr::QrDisplay::frame,
            qontrol::UNIQUE);
    column(this)->addWidget(m_display, 0, Qt::AlignHCenter);
}

HostQrDisplay::~HostQrDisplay() {
    m_engine->stop();
}

void HostQrDisplay::setPayload(const QByteArray &payload) {
    m_engine->request(qr::QrRequest{.payload = payload});
}

void HostQrDisplay::setCodeSize(int size) {
    m_display->setSize(size);
}

void HostQrDisplay::stop() {
    m_engine->stop();
}

// ===== Scan progress =====

HostScanProgress::HostScanProgress(QWidget *parent) : IScanProgressWidget(parent) {
    m_progress = new catalog::ScanProgress(this);
    column(this)->addWidget(m_progress);
}

void HostScanProgress::setProgress(int received, int total) {
    m_progress->setProgress(std::max(0, received), std::max(0, total));
}

// ===== Step trail =====

HostStepTrail::HostStepTrail(QWidget *parent) : IStepTrailWidget(parent) {
    m_layout = column(this);
    rebuild();
}

void HostStepTrail::setSteps(const QStringList &names) {
    m_names = names;
    rebuild();
}

void HostStepTrail::setStepCount(int count) {
    QStringList names;
    for (int i = 0; i < std::max(0, count); ++i) {
        names.append(QString());
    }
    m_names = names;
    rebuild();
}

void HostStepTrail::setCurrent(int index) {
    m_current = std::max(0, index);
    if (m_trail != nullptr) {
        m_trail->setCurrent(m_current);
    }
}

void HostStepTrail::rebuild() {
    if (m_trail != nullptr) {
        m_layout->removeWidget(m_trail);
        delete m_trail;
    }
    m_trail = new catalog::WizardSteps(m_names, this);
    m_trail->setCurrent(m_current);
    m_layout->addWidget(m_trail);
}

// ===== Confirmation modal =====

HostConfirmModal::HostConfirmModal(QWidget *over, plugin::Confirmation request)
    : m_request(std::move(request)) {
    // A plugin's QStringLiteral points into its library, unmapped once it is unloaded:
    // the modal keeps its own copies.
    m_request.title.detach();
    m_request.message.detach();
    m_request.confirmLabel.detach();
    // Over the window holding the plugin's tab, centred there; without one, over the
    // active window as any modal.
    if (over != nullptr) {
        setParent(over->window(), windowFlags());
        connect(over, &QObject::destroyed, this, &HostConfirmModal::onOverDestroyed,
                qontrol::UNIQUE);
    }
    setAttribute(Qt::WA_DeleteOnClose);
    init();
    doConnect();
    view();
}

void HostConfirmModal::init() {
    m_message = new catalog::Label(QString(), catalog::LabelRole::Body);
    m_message->setTextFormat(Qt::PlainText);
    m_message->setWordWrap(true);
    m_cancel_btn = catalog::btnCancel();
    m_confirm_btn =
        new catalog::Button(QString(), m_request.destructive ? catalog::ButtonRole::Destructive
                                                             : catalog::ButtonRole::Primary);
    // The plugin's label sets its width, never under Reckless's own buttons'.
    m_confirm_btn->setWidth(BtnWidth::Auto);
    m_confirm_btn->setMinimumWidth(resolve(BtnWidth::M));
}

void HostConfirmModal::doConnect() {
    connect(m_confirm_btn, &QPushButton::clicked, this, &HostConfirmModal::onConfirmClicked,
            qontrol::UNIQUE);
    connect(m_cancel_btn, &QPushButton::clicked, this, &HostConfirmModal::onCancelClicked,
            qontrol::UNIQUE);
}

void HostConfirmModal::onConfirmClicked() {
    accept();
}

void HostConfirmModal::onCancelClicked() {
    reject();
}

void HostConfirmModal::onOverDestroyed() {
    // The tab is mid-destruction, its children already deleted: the plugin hears nothing
    // back, the modal only closes.
    disconnect(this, &QDialog::finished, nullptr, nullptr);
    disconnect(this, &QDialog::accepted, nullptr, nullptr);
    disconnect(this, &QDialog::rejected, nullptr, nullptr);
    reject();
}

void HostConfirmModal::view() {
    auto *actions = new catalog::ModalActions;
    actions->addAction(m_cancel_btn);
    actions->addAction(m_confirm_btn);
    setBody((new qontrol::Column)->push(m_message));
    setFooter(actions);
    setWidth(ModalWidth::S);
    retranslateUi();
}

void HostConfirmModal::changeEvent(QEvent *event) {
    if (event->type() == QEvent::LanguageChange) {
        retranslateUi();
    }
    catalog::Modal::changeEvent(event);
}

void HostConfirmModal::retranslateUi() {
    // The plugin's own text stays as it gave it; Cancel follows Reckless's language.
    m_message->setText(m_request.message);
    m_confirm_btn->setText(m_request.confirmLabel);
    m_cancel_btn->setText(TR("common-cancel"));
    setWindowTitle(m_request.title);
    adjustSize();
}
