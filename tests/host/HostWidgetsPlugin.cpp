// ws-plaude/silent#121 and #125: a plugin built against the published SDK only. Its tab
// shows Reckless's QR display, scan progress and step trail (Host::createQrDisplay,
// createScanProgress, createStepTrail), and a Count button the user can click while a
// keys flow window is open.
#include "interfaces/host.h"
#include "interfaces/instance.h"
#include "interfaces/module.h"
#include "interfaces/widgets.h"

#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

class Q_DECL_HIDDEN WidgetsInstance final : public QObject, public IInstance {
    Q_OBJECT
    Q_INTERFACES(IInstance)

public:
    explicit WidgetsInstance(QObject *parent) : QObject(parent) {
    }

    ~WidgetsInstance() override {
        delete m_page;
    }

    [[nodiscard]] auto id() const -> QString override {
        return QStringLiteral("host-widgets-instance");
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
        return nullptr;
    }

    auto theme() -> IThemeProvider * override {
        return nullptr;
    }

    void publish() {
        auto *host = Host::get();
        m_page = new QWidget;
        m_page->setObjectName(QStringLiteral("host-widgets-page"));
        auto *trail = host->createStepTrail(m_page);
        trail->setSteps(
            {QStringLiteral("Device"), QStringLiteral("Request"), QStringLiteral("Answer")});
        trail->setCurrent(1);
        auto *display = host->createQrDisplay(m_page);
        display->setCodeSize(240);
        // Long enough for several BBQR parts, so the part count shows.
        display->setPayload(QByteArray(1200, 'r'));
        auto *progress = host->createScanProgress(m_page);
        progress->setProgress(2, 5);
        m_count = new QPushButton(QStringLiteral("Count"), m_page);
        m_count->setObjectName(QStringLiteral("host-widgets-count"));
        m_clicks = new QLabel(QStringLiteral("0"), m_page);
        m_clicks->setObjectName(QStringLiteral("host-widgets-clicks"));
        auto *layout = new QVBoxLayout(m_page);
        layout->addWidget(trail);
        layout->addWidget(display, 0, Qt::AlignHCenter);
        layout->addWidget(progress);
        layout->addWidget(m_count, 0, Qt::AlignHCenter);
        layout->addWidget(m_clicks, 0, Qt::AlignHCenter);
        layout->addStretch();
        connect(m_count, &QPushButton::clicked, this, &WidgetsInstance::onCountClicked);
        auto tab = host->openTab(m_page, this);
        if (tab == 0) {
            qFatal("host widgets fixture: its tab did not open");
        }
        host->setTabTitle(tab, QStringLiteral("Widgets"));
    }

public slots:

    void onCountClicked() {
        ++m_count_value;
        m_clicks->setText(QString::number(m_count_value));
    }

private:
    QPointer<QWidget> m_page;
    QPushButton *m_count = nullptr;
    QLabel *m_clicks = nullptr;
    int m_count_value = 0;
};

class Q_DECL_HIDDEN WidgetsModule final : public IModule {
    Q_OBJECT

public:
    using IModule::IModule;

    void shutdown(ReqId req_id) override {
        qDeleteAll(findChildren<WidgetsInstance *>(QString(), Qt::FindDirectChildrenOnly));
        emit shutdownFinished(req_id, QString());
    }

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override {
        return {{QStringLiteral("id"), QStringLiteral("host.widgets.module")}};
    }

    auto list() -> ReqId override {
        emit instances(1, {{QStringLiteral("host-widgets-instance"), QStringLiteral("Widgets")}});
        return 1;
    }

    auto autoStart() -> ReqId override {
        emit IModule::autoStart(2, {});
        return 2;
    }

    void startInstance([[maybe_unused]] const QString &id) override {
        auto *instance = new WidgetsInstance(this);
        Host::get()->registerInstance(instance->id(), instance, this);
        instance->publish();
    }
};

class Q_DECL_HIDDEN HostWidgetsPlugin final : public QObject, public IPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID RECKLESS_IPlugin_IID)
    Q_INTERFACES(IPlugin)

public:
    HostWidgetsPlugin() : m_module(new WidgetsModule(this)) {
    }

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override {
        return {{QStringLiteral("id"), QStringLiteral("host.widgets.fixture")}};
    }

    [[nodiscard]] auto modules() const -> QList<IModule *> override {
        return {m_module};
    }

private:
    WidgetsModule *m_module = nullptr;
};

#include "HostWidgetsPlugin.moc"
