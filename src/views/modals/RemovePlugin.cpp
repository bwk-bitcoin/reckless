#include "RemovePlugin.h"

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

RemovePlugin::RemovePlugin(QString plugin_id, QString name)
    : m_plugin_id(std::move(plugin_id)),
      m_name(std::move(name)) {
    init();
    doConnect();
    view();
}

void RemovePlugin::init() {
    m_question = new catalog::Label(QString(), catalog::LabelRole::Body);
    m_question->setWordWrap(true);
    m_warning = new catalog::Notice(catalog::Notice::Tone::Warning);
    m_remove_btn = catalog::btnRemovePlugin();
}

void RemovePlugin::doConnect() {
    connect(m_remove_btn, &QPushButton::clicked, this, &RemovePlugin::onRemoveClicked,
            qontrol::UNIQUE);
}

void RemovePlugin::onRemoveClicked() {
    emit confirmed(m_plugin_id);
    accept();
}

void RemovePlugin::view() {
    auto *actions = new catalog::ModalActions;
    actions->addAction(m_remove_btn);
    setBody((new qontrol::Column)->spacing(resolve(Spacing::M))->push(m_question)->push(m_warning));
    setFooter(actions);
    setWidth(ModalWidth::S);
    retranslateUi();
}

void RemovePlugin::changeEvent(QEvent *event) {
    if (event->type() == QEvent::LanguageChange) {
        retranslateUi();
    }
    catalog::Modal::changeEvent(event);
}

void RemovePlugin::retranslateUi() {
    m_question->setText(TR("settings-remove-question").arg(m_name));
    m_warning->setText(TR("settings-remove-warning"));
    m_remove_btn->setText(TR("btn-remove-plugin"));
    setWindowTitle(TR("settings-remove-plugin"));
    adjustSize();
}

} // namespace modal
