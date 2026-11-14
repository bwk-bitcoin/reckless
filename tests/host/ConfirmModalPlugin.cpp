// ws-plaude/silent#127: a plugin built against the published SDK only, asking the user to
// confirm in Reckless's own modal (Host::createConfirmModal) from its tab.
#include "interfaces/host.h"
#include "interfaces/instance.h"
#include "interfaces/module.h"

#include <QDialog>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

class Q_DECL_HIDDEN ConfirmInstance final : public QObject, public IInstance {
    Q_OBJECT
    Q_INTERFACES(IInstance)

public:
    explicit ConfirmInstance(QObject *parent) : QObject(parent) {
    }

    ~ConfirmInstance() override {
        delete m_page;
    }

    [[nodiscard]] auto id() const -> QString override {
        return QStringLiteral("confirm-modal-instance");
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
        m_page = new QWidget;
        m_page->setObjectName(QStringLiteral("confirm-plugin-page"));
        m_reset = new QPushButton(QStringLiteral("Reset all results"), m_page);
        m_reset->setObjectName(QStringLiteral("confirm-plugin-reset"));
        m_answer = new QLabel(m_page);
        m_answer->setObjectName(QStringLiteral("confirm-plugin-answer"));
        auto *layout = new QVBoxLayout(m_page);
        layout->addWidget(m_reset);
        layout->addWidget(m_answer);
        layout->addStretch();
        connect(m_reset, &QPushButton::clicked, this, &ConfirmInstance::onResetClicked);
        auto tab = Host::get()->openTab(m_page, this);
        if (tab == 0) {
            qFatal("confirm modal fixture: its tab did not open");
        }
        Host::get()->setTabTitle(tab, QStringLiteral("Confirm"));
    }

public slots:

    void onResetClicked() {
        auto *modal = Host::get()->createConfirmModal(
            m_page,
            {.title = QStringLiteral("Reset all results"),
             .message = QStringLiteral("Every saved result of the conformance run is deleted. "
                                       "This cannot be undone."),
             .confirmLabel = QStringLiteral("Reset all results"),
             .destructive = true});
        connect(modal, &QDialog::accepted, this, &ConfirmInstance::onConfirmed);
        connect(modal, &QDialog::rejected, this, &ConfirmInstance::onCancelled);
        modal->open();
    }

    void onConfirmed() {
        m_answer->setText(QStringLiteral("confirmed"));
    }

    void onCancelled() {
        m_answer->setText(QStringLiteral("cancelled"));
    }

private:
    QPointer<QWidget> m_page;
    QPushButton *m_reset = nullptr;
    QLabel *m_answer = nullptr;
};

class Q_DECL_HIDDEN ConfirmModule final : public IModule {
    Q_OBJECT

public:
    using IModule::IModule;

    void shutdown(ReqId req_id) override {
        qDeleteAll(findChildren<ConfirmInstance *>(QString(), Qt::FindDirectChildrenOnly));
        emit shutdownFinished(req_id, QString());
    }

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override {
        return {{QStringLiteral("id"), QStringLiteral("confirm.modal.module")}};
    }

    auto list() -> ReqId override {
        emit instances(1, {{QStringLiteral("confirm-modal-instance"), QStringLiteral("Confirm")}});
        return 1;
    }

    auto autoStart() -> ReqId override {
        emit IModule::autoStart(2, {});
        return 2;
    }

    void startInstance([[maybe_unused]] const QString &id) override {
        auto *instance = new ConfirmInstance(this);
        Host::get()->registerInstance(instance->id(), instance, this);
        instance->publish();
    }
};

class Q_DECL_HIDDEN ConfirmModalPlugin final : public QObject, public IPlugin {
    Q_OBJECT
    Q_PLUGIN_METADATA(IID RECKLESS_IPlugin_IID)
    Q_INTERFACES(IPlugin)

public:
    ConfirmModalPlugin() : m_module(new ConfirmModule(this)) {
    }

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override {
        return {{QStringLiteral("id"), QStringLiteral("confirm.modal.fixture")}};
    }

    [[nodiscard]] auto modules() const -> QList<IModule *> override {
        return {m_module};
    }

private:
    ConfirmModule *m_module = nullptr;
};

#include "ConfirmModalPlugin.moc"
