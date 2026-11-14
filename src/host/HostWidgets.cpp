#include "HostWidgets.h"

#include "catalog/display/WizardSteps.h"
#include "catalog/feedback/ScanProgress.h"
#include "modules/keys/flow/QrSettings.h"
#include "qr/QrDisplay.h"
#include "qr/QrTypes.h"
#include "qr/bbqr/BbqrDisplayEngine.h"

#include <QVBoxLayout>
#include <Qontrol>
#include <algorithm>
#include <common.h>

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
