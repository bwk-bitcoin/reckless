#include "DisablePlugin.h"

#include "catalog/Button.h"
#include "catalog/Variants.h"
#include "catalog/containers/ModalActions.h"
#include "catalog/display/Label.h"
#include "catalog/feedback/Notice.h"
#include "i18n/Tr.h"
#include "theme/Palette.h"

#include <Qontrol>
#include <common.h>
#include <utility>

namespace modal {

using catalog::Notice;

DisablePlugin::DisablePlugin(QString plugin_id, QString name, QString meta, QStringList accounts,
                             QStringList themes)
    : m_plugin_id(std::move(plugin_id)),
      m_name(std::move(name)),
      m_meta(std::move(meta)),
      m_accounts(std::move(accounts)),
      m_themes(std::move(themes)) {
    init();
    doConnect();
    view();
}

void DisablePlugin::init() {
    m_question = new catalog::Label(QString(), catalog::LabelRole::Body);
    m_question->setWordWrap(true);
    m_accounts_notice = new Notice;
    m_themes_notice = new Notice;
    m_cancel_btn = catalog::btnCancel();
    m_disable_btn = catalog::btnDisablePlugin();
}

void DisablePlugin::doConnect() {
    connect(m_disable_btn, &QPushButton::clicked, this, &DisablePlugin::onDisableClicked,
            qontrol::UNIQUE);
    connect(m_cancel_btn, &QPushButton::clicked, this, &DisablePlugin::onCancelClicked,
            qontrol::UNIQUE);
}

void DisablePlugin::onDisableClicked() {
    emit confirmed(m_plugin_id);
    accept();
}

void DisablePlugin::onCancelClicked() {
    reject();
}

void DisablePlugin::view() {
    auto *actions = new catalog::ModalActions;
    actions->addAction(m_cancel_btn);
    actions->addAction(m_disable_btn);
    setBody((new qontrol::Column)
                ->spacing(resolve(Spacing::M))
                ->push(m_question)
                ->push(m_accounts_notice)
                ->push(m_themes_notice));
    setFooter(actions);
    setWidth(ModalWidth::S);
    retranslateUi();
}

void DisablePlugin::changeEvent(QEvent *event) {
    if (event->type() == QEvent::LanguageChange) {
        retranslateUi();
    }
    catalog::Modal::changeEvent(event);
}

void DisablePlugin::retranslateUi() {
    m_question->setText(TR("settings-disable-question").arg(m_name, m_meta));
    if (m_accounts.isEmpty()) {
        m_accounts_notice->setTone(Notice::Tone::Info);
        m_accounts_notice->setTitle(QString());
        m_accounts_notice->setText(TR("settings-disable-no-account"));
    } else if (m_accounts.size() == 1) {
        m_accounts_notice->setTone(Notice::Tone::Warning);
        m_accounts_notice->setTitle(TR("settings-disable-account-one"));
        m_accounts_notice->setText(TR("settings-disable-account-one-text").arg(m_accounts.first()));
    } else {
        m_accounts_notice->setTone(Notice::Tone::Warning);
        m_accounts_notice->setTitle(TR("settings-disable-accounts").arg(m_accounts.size()));
        m_accounts_notice->setText(
            TR("settings-disable-accounts-text").arg(m_accounts.join(QStringLiteral(", "))));
    }
    m_themes_notice->setTone(Notice::Tone::Info);
    m_themes_notice->setText(TR("settings-disable-themes").arg(m_themes.join(QStringLiteral(", "))));
    m_themes_notice->setVisible(!m_themes.isEmpty());
    m_cancel_btn->setText(TR("common-cancel"));
    m_disable_btn->setText(TR("btn-disable-plugin"));
    setWindowTitle(TR("settings-disable-title"));
    adjustSize();
}

} // namespace modal
