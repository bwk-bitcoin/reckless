#pragma once

#include <QByteArray>
#include <QStringList>
#include <QWidget>

// Reckless's own widgets, made by the host for a plugin's views (ws-plaude/silent#121):
// the plugin hands data in, the host draws them in its live theme, so a plugin's QR
// codes and flows look like Reckless's and follow theme changes. Each is a plain
// QWidget the plugin places in its layouts and owns like any child it creates; create
// them with Host::createQrDisplay(), createScanProgress() and createStepTrail(), on the
// GUI thread.

// An animated multi-part QR code with Reckless's "Part m / n" count under it.
class IQrDisplayWidget : public QWidget {
public:
    using QWidget::QWidget;
    ~IQrDisplayWidget() override = default;
    IQrDisplayWidget(const IQrDisplayWidget &) = delete;
    auto operator=(const IQrDisplayWidget &) -> IQrDisplayWidget & = delete;
    IQrDisplayWidget(IQrDisplayWidget &&) = delete;
    auto operator=(IQrDisplayWidget &&) -> IQrDisplayWidget & = delete;

    // Shows `payload`, split into BBQR parts with the QR settings picked in Reckless
    // (density, contrast, speed), cycling through them. A new payload replaces it.
    virtual void setPayload(const QByteArray &payload) = 0;
    // The code's square side, in pixels; Reckless's default until set.
    virtual void setCodeSize(int size) = 0;
    // Stops cycling the parts; setPayload() starts again.
    virtual void stop() = 0;
};

// Reckless's multi-part scan feedback: one segment per part, filled once received, over
// "m of n parts".
class IScanProgressWidget : public QWidget {
public:
    using QWidget::QWidget;
    ~IScanProgressWidget() override = default;
    IScanProgressWidget(const IScanProgressWidget &) = delete;
    auto operator=(const IScanProgressWidget &) -> IScanProgressWidget & = delete;
    IScanProgressWidget(IScanProgressWidget &&) = delete;
    auto operator=(IScanProgressWidget &&) -> IScanProgressWidget & = delete;

    // `received` of `total` parts; a total of 0 shows nothing received yet.
    virtual void setProgress(int received, int total) = 0;
};

// Reckless's wizard step trail: numbered dots, done steps checked, the current one in
// the accent colour.
class IStepTrailWidget : public QWidget {
public:
    using QWidget::QWidget;
    ~IStepTrailWidget() override = default;
    IStepTrailWidget(const IStepTrailWidget &) = delete;
    auto operator=(const IStepTrailWidget &) -> IStepTrailWidget & = delete;
    IStepTrailWidget(IStepTrailWidget &&) = delete;
    auto operator=(IStepTrailWidget &&) -> IStepTrailWidget & = delete;

    // The steps by name. It may be called again while the flow runs, with a longer
    // list when the flow learns its next steps; the current step stays.
    virtual void setSteps(const QStringList &names) = 0;
    // `count` numbered steps without names, for a flow that names none.
    virtual void setStepCount(int count) = 0;
    // The current step, 0-based: the ones before it show done.
    virtual void setCurrent(int index) = 0;
};
