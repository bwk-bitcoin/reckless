#pragma once

#include <QHash>
#include <QString>
#include <QStringList>
#include <qevent.h>

#include "catalog/containers/Modal.h"

namespace catalog {
class Button;
class Label;
class Notice;
} // namespace catalog

namespace modal {

// The confirmation of disabling a plugin, over the Settings tab
// (ws-plaude/silent#124): names the plugin and its version, the accounts that use it and
// the themes it provides. Cancel, or closing it, leaves the plugin enabled.
class DisablePlugin : public catalog::Modal {
    Q_OBJECT

public:
    // `meta` is the plugin's id and version line, `accounts` the names of the accounts
    // that use it, `themes` the themes it provides.
    DisablePlugin(QString plugin_id, QString name, QString meta, QStringList accounts,
                  QStringList themes);

signals:
    void confirmed(const QString &plugin_id);

public slots:
    void onDisableClicked();
    void onCancelClicked();

protected:
    void init();
    void doConnect();
    void view();
    void changeEvent(QEvent *event) override;
    void retranslateUi();

private:
    QString m_plugin_id;
    QString m_name;
    QString m_meta;
    QStringList m_accounts;
    QStringList m_themes;
    catalog::Label *m_question = nullptr;
    catalog::Notice *m_accounts_notice = nullptr;
    catalog::Notice *m_themes_notice = nullptr;
    catalog::Button *m_cancel_btn = nullptr;
    catalog::Button *m_disable_btn = nullptr;
};

} // namespace modal
