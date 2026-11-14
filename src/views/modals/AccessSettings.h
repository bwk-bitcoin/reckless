#pragma once

#include <QHash>
#include <QString>
#include <cstdint>
#include <reckless.h>

#include "catalog/containers/Modal.h"

namespace catalog {
class Button;
class Label;
class ModalActions;
class Notice;
class SelectRow;
class Spinner;
} // namespace catalog

class PluginRegistry;
class QWidget;

namespace modal {

// What an external plugin may use, in a modal over the Settings tab
// (ws-plaude/silent#128): one row per library version answered, its Accounts and Keys
// grants changed at once, and Forget, after which the plugin is asked again on its next
// use. The answers are read with the plugin's storage epoch when the modal opens; a
// change refused because the plugin was removed since, or any other failed read or
// save, shows the error and disables the rows until Try Again reads them anew. Reads and
// saves run off the GUI thread, one at a time: the rows are disabled while one runs, and
// an answer to an earlier one is ignored. Closing it (Close, Escape, the titlebar) keeps
// what was saved; it closes by itself once its plugin is removed. It deletes itself once
// closed.
class AccessSettings final : public catalog::Modal {
    Q_OBJECT

public:
    // Window-modal over the window holding `over`.
    AccessSettings(PluginRegistry *registry, QString id, QWidget *over);

public slots:
    void onCloseClicked();
    void onPluginStopFinished(const QString &plugin_id, bool removed, const QString &error);
    void onGrantClicked(bool allowed);
    void onForgetClicked();
    void onReloadClicked();
    void onHistoryRead(uint64_t revision, const PluginAccessHistory &history);
    void onSaved(uint64_t revision, const QString &error);

protected:
    void init();
    void doConnect();
    void view();

    // Access view
    void initAccess();
    void connectAccess();
    [[nodiscard]] auto viewAccess() -> QWidget *;
    void showAccess();
    void loadRows();
    void showRows(const PluginAccessHistory &history);
    void save(const PluginAccess &entry);
    void resetToggles(const QString &hash);
    [[nodiscard]] auto rowSub(const PluginAccess &entry) const -> QString;
    void setBusy(bool busy);
    void showFailure(const QString &error);

private:
    PluginRegistry *m_plugin_registry = nullptr;
    QString m_id;
    // The plugin's storage epoch read with the rows: every change is saved against it.
    uint64_t m_epoch = 0;
    // The read or save running, the last one started: an answer to another is ignored.
    uint64_t m_revision = 0;
    // The answers the running save stores.
    PluginAccess m_saving;
    // The answers each row shows, and the row, by library hash.
    QHash<QString, PluginAccess> m_entries;
    QHash<QString, catalog::SelectRow *> m_entry_rows;

    QWidget *m_access = nullptr;
    catalog::Label *m_access_text = nullptr;
    catalog::Notice *m_notice = nullptr;
    catalog::Button *m_reload_btn = nullptr;
    catalog::Spinner *m_busy = nullptr;
    qontrol::Column *m_rows = nullptr;
    catalog::Label *m_empty = nullptr;
    catalog::ModalActions *m_access_actions = nullptr;
    catalog::Button *m_close_btn = nullptr;
};

} // namespace modal
