#pragma once

#include <QString>
#include <qevent.h>

#include "catalog/containers/Modal.h"

namespace catalog {
class Button;
class Label;
class Notice;
} // namespace catalog

namespace modal {

// The destructive confirmation of a plugin's removal, over the Settings tab
// (ws-plaude/silent#108): names the plugin and warns that all of its data goes.
class RemovePlugin : public catalog::Modal {
    Q_OBJECT

public:
    RemovePlugin(QString plugin_id, QString name);

signals:
    void confirmed(const QString &plugin_id);

public slots:
    void onRemoveClicked();

protected:
    void init();
    void doConnect();
    void view();
    void changeEvent(QEvent *event) override;
    void retranslateUi();

private:
    QString m_plugin_id;
    QString m_name;
    catalog::Label *m_question = nullptr;
    catalog::Notice *m_warning = nullptr;
    catalog::Button *m_remove_btn = nullptr;
};

} // namespace modal
