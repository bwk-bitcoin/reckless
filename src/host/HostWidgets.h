#pragma once

#include "catalog/containers/Modal.h"
#include "interfaces/types.h"
#include "interfaces/widgets.h"

namespace catalog {
class Button;
class Label;
class ScanProgress;
class WizardSteps;
} // namespace catalog

namespace qr {
class BbqrDisplayEngine;
class QrDisplay;
} // namespace qr

class QEvent;
class QVBoxLayout;

// The host's widgets behind interfaces/widgets.h (ws-plaude/silent#121): Reckless's own
// QR display, scan progress and step trail, wrapped for plugins, and its confirmation
// modal (#127).

class HostQrDisplay final : public IQrDisplayWidget {
public:
    explicit HostQrDisplay(QWidget *parent = nullptr);
    ~HostQrDisplay() override;
    HostQrDisplay(const HostQrDisplay &) = delete;
    auto operator=(const HostQrDisplay &) -> HostQrDisplay & = delete;
    HostQrDisplay(HostQrDisplay &&) = delete;
    auto operator=(HostQrDisplay &&) -> HostQrDisplay & = delete;

    void setPayload(const QByteArray &payload) override;
    void setCodeSize(int size) override;
    void stop() override;

private:
    qr::QrDisplay *m_display = nullptr;
    qr::BbqrDisplayEngine *m_engine = nullptr;
};

class HostScanProgress final : public IScanProgressWidget {
public:
    explicit HostScanProgress(QWidget *parent = nullptr);
    ~HostScanProgress() override = default;
    HostScanProgress(const HostScanProgress &) = delete;
    auto operator=(const HostScanProgress &) -> HostScanProgress & = delete;
    HostScanProgress(HostScanProgress &&) = delete;
    auto operator=(HostScanProgress &&) -> HostScanProgress & = delete;

    void setProgress(int received, int total) override;

private:
    catalog::ScanProgress *m_progress = nullptr;
};

class HostStepTrail final : public IStepTrailWidget {
public:
    explicit HostStepTrail(QWidget *parent = nullptr);
    ~HostStepTrail() override = default;
    HostStepTrail(const HostStepTrail &) = delete;
    auto operator=(const HostStepTrail &) -> HostStepTrail & = delete;
    HostStepTrail(HostStepTrail &&) = delete;
    auto operator=(HostStepTrail &&) -> HostStepTrail & = delete;

    void setSteps(const QStringList &names) override;
    void setStepCount(int count) override;
    void setCurrent(int index) override;

private:
    // WizardSteps takes its steps once: a new list builds a new trail in its place.
    void rebuild();

    QVBoxLayout *m_layout = nullptr;
    catalog::WizardSteps *m_trail = nullptr;
    QStringList m_names;
    int m_current = 0;
};

// Reckless's confirmation, laid out like RemovePlugin and DisablePlugin
// (ws-plaude/silent#127): the plugin's message over Cancel and its confirm button.
class HostConfirmModal final : public catalog::Modal {
    Q_OBJECT

public:
    HostConfirmModal(QWidget *over, plugin::Confirmation request);

public slots:
    void onConfirmClicked();
    void onCancelClicked();
    // The plugin's tab went (its plugin disabled or removed): nothing is left to
    // confirm, and the modal closes without answering.
    void onOverDestroyed();

protected:
    void init();
    void doConnect();
    void view();
    void changeEvent(QEvent *event) override;
    void retranslateUi();

private:
    plugin::Confirmation m_request;
    catalog::Label *m_message = nullptr;
    catalog::Button *m_cancel_btn = nullptr;
    catalog::Button *m_confirm_btn = nullptr;
};
