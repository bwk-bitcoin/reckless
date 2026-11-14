#pragma once

#include "host/PluginRegistry.h"
#include <QList>
#include <QPointer>
#include <QString>
#include <QWidget>

namespace catalog {
class Button;
class Label;
} // namespace catalog

#include <Qontrol>

class Host;
class HostEvents;
class IModule;

class MenuTab : public QWidget {
    Q_OBJECT

public:
    explicit MenuTab(QWidget *parent = nullptr);

signals:
    void createAccount();

public slots:
    void onAccountList(const QList<QString> &accounts);
    void onCreateClicked();
    void onItemClicked();
    void onTrashClicked();
    void onDeleteConfirmed(const QString &name);
    void onAccountDeletionFinished(IModule *module, const QString &id, const QString &error);
    void onHostInstanceChanged(const QString &id);
    void onHostSettingsChanged();
    void onPluginRegistryChanged();
    void onRefreshLauncherItems();

protected:
    void init();
    void doConnect();
    void view();
    void clearRows();
    void rebuildRows();
    // The logo for the theme now applied (ws-plaude/silent#120).
    void refreshLogo();
    void changeEvent(QEvent *event) override;

private:
    struct LauncherEntry {
        IModule *module = nullptr;
        QString id;
        QString name;
    };

    catalog::Button *m_create_btn = nullptr;
    // The full reckless logo over the accounts: its dark letters on a light theme, its
    // white ones on a dark theme.
    catalog::Label *m_logo = nullptr;
    qontrol::Column *m_accounts_column = nullptr;
    QList<QWidget *> m_rows;
    QList<LauncherEntry> m_entries;
    // The account types, as the Account Type modal lists them.
    QList<PluginRegistry::CreatorLauncher> m_creators;
    QPointer<IModule> m_pending_delete_module;
    QString m_pending_delete_id;
    Host *m_host = nullptr;
    HostEvents *m_host_events = nullptr;
};
