#include "AccessSettings.h"

#include "catalog/Button.h"
#include "catalog/ClearRows.h"
#include "catalog/SelectRow.h"
#include "catalog/Variants.h"
#include "catalog/containers/ModalActions.h"
#include "catalog/display/Label.h"
#include "catalog/feedback/Notice.h"
#include "catalog/feedback/Spinner.h"
#include "catalog/inputs/Toggle.h"
#include "host/HostWidgets.h"
#include "host/PluginAccess.h"
#include "host/PluginRegistry.h"
#include "i18n/Tr.h"
#include "theme/Icon.h"
#include "theme/Palette.h"

#include <QStringList>
#include <Qontrol>
#include <common.h>

#include <string>
#include <tuple>
#include <utility>

namespace modal {

using catalog::Label;
using catalog::LabelRole;
using catalog::LabelTone;

namespace {
constexpr const char *K_HASH = "accessHash";
constexpr const char *K_GRANT = "accessGrant";
constexpr const char *GRANT_ACCOUNT = "account";
constexpr const char *GRANT_KEYS = "keys";
constexpr const char *GRANT_STATE = "state";
// The hash as a row shows it: enough to tell two versions apart, short enough to
// leave room for the three grants.
constexpr int SHORT_HASH = 8;

auto toQString(const rust::String &value) -> QString {
    return QString::fromStdString(std::string(value));
}

auto grantToggle(PluginGrant grant, const QString &hash, const char *which) -> catalog::Toggle * {
    auto *toggle = new catalog::Toggle;
    toggle->setChecked(grant == PluginGrant::Allowed);
    toggle->setProperty(K_HASH, hash);
    toggle->setProperty(K_GRANT, QString::fromLatin1(which));
    return toggle;
}
} // namespace

AccessSettings::AccessSettings(PluginRegistry *registry, QString id, QWidget *over)
    : m_plugin_registry(registry),
      m_id(std::move(id)) {
    if (over != nullptr) {
        setParent(over->window(), windowFlags());
    }
    setAttribute(Qt::WA_DeleteOnClose);
    init();
    doConnect();
    view();
}

void AccessSettings::init() {
    initAccess();
}

void AccessSettings::doConnect() {
    connectAccess();
}

void AccessSettings::view() {
    m_access = viewAccess();
    showAccess();
}

// ===== Access view =====

void AccessSettings::initAccess() {
    m_access_text = new Label(LabelRole::Body);
    m_access_text->setWordWrap(true);
    m_access_text->setTone(LabelTone::Secondary);
    m_notice = new catalog::Notice(catalog::Notice::Tone::Error);
    m_notice->setTitle(TR("plugin-access-flow-failed"));
    m_reload_btn = catalog::btnTryAgain();
    m_notice->setAction(m_reload_btn);
    m_notice->setVisible(false);
    m_busy = new catalog::Spinner(metric::ROW_SPINNER_SIZE);
    m_busy->setVisible(false);
    m_rows = new qontrol::Column;
    m_rows->spacing(resolve(Spacing::S));
    m_empty = new Label(LabelRole::Caption);
    m_empty->setTone(LabelTone::Muted);
    m_empty->setWordWrap(true);
    m_access_actions = new catalog::ModalActions;
    m_close_btn = catalog::btnClose();
    m_access_actions->addAction(m_close_btn);
}

void AccessSettings::connectAccess() {
    connect(m_reload_btn, &QPushButton::clicked, this, &AccessSettings::onReloadClicked,
            qontrol::UNIQUE);
    connect(m_close_btn, &QPushButton::clicked, this, &AccessSettings::onCloseClicked,
            qontrol::UNIQUE);
    if (m_plugin_registry != nullptr) {
        connect(m_plugin_registry, &PluginRegistry::pluginStopFinished, this,
                &AccessSettings::onPluginStopFinished, qontrol::UNIQUE);
    }
}

auto AccessSettings::viewAccess() -> QWidget * {
    auto *column = (new qontrol::Column)
                       ->spacing(resolve(Spacing::M))
                       ->push(m_access_text)
                       ->push(m_notice)
                       ->push(m_busy)
                       ->push(m_rows)
                       ->push(m_empty);
    // The main view's width, whatever the rows hold.
    column->setFixedWidth(metric::SETTINGS_BODY_WIDTH);
    return column;
}

void AccessSettings::showAccess() {
    QString name = m_plugin_registry->pluginName(m_id);
    m_access_text->setText(TR("plugin-access-flow-text").arg(name));
    loadRows();
    setBody(m_access);
    setFooter(m_access_actions);
    // The narrowest modal holding the settings body's width with its padding.
    setWidth(ModalWidth::Wizard);
    setWindowTitle(TR("plugin-access-flow-title").arg(name));
}

void AccessSettings::loadRows() {
    setBusy(true);
    auto *job = new pluginaccess::Job;
    connect(job, &pluginaccess::Job::historyRead, this, &AccessSettings::onHistoryRead,
            qontrol::UNIQUE);
    job->history(++m_revision, m_id);
}

void AccessSettings::showRows(const PluginAccessHistory &history) {
    // clear() also resets the layout spacing.
    catalog::clearRows(m_rows);
    m_rows->spacing(resolve(Spacing::S));
    m_entries.clear();
    m_entry_rows.clear();
    m_epoch = history.storage_epoch;
    m_notice->setVisible(false);
    m_rows->setEnabled(true);
    for (const auto &entry : history.entries) {
        QString hash = toQString(entry.hash);

        auto *grants = new qontrol::Row;
        for (const auto &[grant, which, label] :
             {std::tuple{entry.account, GRANT_ACCOUNT, TR("plugin-access-accounts")},
              std::tuple{entry.keys, GRANT_KEYS, TR("plugin-access-keys")},
              std::tuple{entry.state, GRANT_STATE, TR("plugin-access-state")}}) {
            auto *toggle = grantToggle(grant, hash, which);
            connect(toggle, &QCheckBox::clicked, this, &AccessSettings::onGrantClicked,
                    qontrol::UNIQUE);
            auto *caption = new Label(LabelRole::Caption);
            caption->setText(label);
            grants->push(caption)
                ->pushSpacer(resolve(Spacing::XS))
                ->push(toggle)
                ->pushSpacer(resolve(Spacing::S));
        }
        auto *forget = catalog::btnForgetAccess();
        forget->setProperty(K_HASH, hash);
        connect(forget, &QPushButton::clicked, this, &AccessSettings::onForgetClicked,
                qontrol::UNIQUE);
        grants->push(forget);

        auto *row = new catalog::SelectRow;
        row->setIcon(icon::puzzle);
        row->setTitle(TR("plugin-access-library").arg(hash.left(SHORT_HASH)));
        row->setSub(rowSub(entry));
        row->setTrailing(grants);
        row->setChevron(false);
        row->setClickable(false);
        m_rows->push(row);
        row->show();
        m_entries.insert(hash, entry);
        m_entry_rows.insert(hash, row);
    }
    m_empty->setText(TR("plugin-access-none"));
    m_empty->setVisible(m_entries.isEmpty());
}

// Saved against the epoch the rows were read with; the rows wait disabled for the answer.
void AccessSettings::save(const PluginAccess &entry) {
    m_saving = entry;
    setBusy(true);
    auto *job = new pluginaccess::Job;
    connect(job, &pluginaccess::Job::saved, m_plugin_registry, &PluginRegistry::onPluginAccessSaved,
            qontrol::UNIQUE);
    connect(job, &pluginaccess::Job::saved, this, &AccessSettings::onSaved, qontrol::UNIQUE);
    job->save(++m_revision, entry, m_epoch);
}

// Back to the answers kept for `hash`: setChecked() does not emit clicked.
void AccessSettings::resetToggles(const QString &hash) {
    auto *row = m_entry_rows.value(hash, nullptr);
    if (row == nullptr) {
        return;
    }
    auto entry = m_entries.value(hash);
    for (auto *toggle : row->findChildren<QCheckBox *>()) {
        QString which = toggle->property(K_GRANT).toString();
        auto grant = entry.state;
        if (which == QLatin1String(GRANT_ACCOUNT)) {
            grant = entry.account;
        } else if (which == QLatin1String(GRANT_KEYS)) {
            grant = entry.keys;
        }
        toggle->setChecked(grant == PluginGrant::Allowed);
    }
}

auto AccessSettings::rowSub(const PluginAccess &entry) const -> QString {
    QString hash = toQString(entry.hash);
    QString sub = hash == m_plugin_registry->pluginHash(m_id) ? TR("plugin-access-current")
                                                              : TR("plugin-access-earlier");
    QStringList unasked;
    for (const auto &[grant, label] : {std::pair{entry.account, TR("plugin-access-accounts")},
                                       std::pair{entry.keys, TR("plugin-access-keys")},
                                       std::pair{entry.state, TR("plugin-access-state")}}) {
        if (grant == PluginGrant::Unasked) {
            unasked.append(label);
        }
    }
    if (!unasked.isEmpty()) {
        sub +=
            QLatin1Char(' ') + TR("plugin-access-unasked").arg(unasked.join(QStringLiteral(", ")));
    }
    return sub;
}

// While a read or save runs, Try Again and the rows wait disabled, the spinner shown.
void AccessSettings::setBusy(bool busy) {
    m_busy->setVisible(busy);
    m_reload_btn->setEnabled(!busy);
    m_rows->setEnabled(!busy);
}

// The rows stay as read, disabled: only Try Again, reading them anew, enables them.
void AccessSettings::showFailure(const QString &error) {
    m_notice->setText(TR("plugin-access-flow-retry").arg(error));
    m_notice->setVisible(true);
    m_rows->setEnabled(false);
}

// ===== Slots =====

void AccessSettings::onCloseClicked() {
    // Every change was saved as it was made: closing keeps them.
    reject();
}

// Its plugin removed, nothing is left to show: the modal closes by itself.
void AccessSettings::onPluginStopFinished(const QString &plugin_id, bool removed,
                                          const QString &error) {
    if (removed && error.isEmpty() && plugin_id == m_id) {
        reject();
    }
}

void AccessSettings::onGrantClicked(bool allowed) {
    auto *toggle = qobject_cast<QCheckBox *>(sender());
    if (toggle == nullptr) {
        return;
    }
    QString hash = toggle->property(K_HASH).toString();
    if (!m_entries.contains(hash)) {
        return;
    }
    auto entry = m_entries.value(hash);
    auto grant = allowed ? PluginGrant::Allowed : PluginGrant::Denied;
    QString which = toggle->property(K_GRANT).toString();
    if (which == QLatin1String(GRANT_ACCOUNT)) {
        entry.account = grant;
    } else if (which == QLatin1String(GRANT_KEYS)) {
        entry.keys = grant;
    } else {
        entry.state = grant;
    }
    save(entry);
}

void AccessSettings::onForgetClicked() {
    auto *button = sender();
    if (button == nullptr) {
        return;
    }
    QString hash = button->property(K_HASH).toString();
    if (!m_entries.contains(hash)) {
        return;
    }
    // Confirmed first (ws-plaude/silent#131), in the modal Reckless gives plugins
    // (#127), over this one: Cancel, Escape or closing it changes nothing.
    m_forget_hash = hash;
    auto *confirm = new HostConfirmModal(
        this, {.title = TR("plugin-access-forget-title"),
               .message = TR("plugin-access-forget-text")
                              .arg(m_plugin_registry->pluginName(m_id), hash.left(SHORT_HASH)),
               .confirmLabel = TR("btn-forget-access"),
               .destructive = true});
    connect(confirm, &QDialog::accepted, this, &AccessSettings::onForgetConfirmed, qontrol::UNIQUE);
    connect(confirm, &QDialog::rejected, this, &AccessSettings::onForgetCancelled, qontrol::UNIQUE);
    confirm->open();
}

void AccessSettings::onForgetConfirmed() {
    QString hash = std::exchange(m_forget_hash, QString());
    // The rows read anew while it was open: the answer it named may be gone.
    if (!m_entries.contains(hash)) {
        return;
    }
    auto entry = m_entries.value(hash);
    entry.account = PluginGrant::Unasked;
    entry.keys = PluginGrant::Unasked;
    entry.state = PluginGrant::Unasked;
    save(entry);
}

void AccessSettings::onForgetCancelled() {
    m_forget_hash.clear();
}

void AccessSettings::onReloadClicked() {
    loadRows();
}

// A failed read keeps the rows read last, disabled; only a successful one takes its epoch.
void AccessSettings::onHistoryRead(uint64_t revision, const PluginAccessHistory &history) {
    if (revision != m_revision) {
        return;
    }
    setBusy(false);
    if (!history.is_ok) {
        showFailure(toQString(history.error));
        return;
    }
    showRows(history);
}

void AccessSettings::onSaved(uint64_t revision, const QString &error) {
    if (revision != m_revision) {
        return;
    }
    setBusy(false);
    QString hash = toQString(m_saving.hash);
    if (!error.isEmpty()) {
        resetToggles(hash);
        showFailure(error);
        return;
    }
    bool forgotten = m_saving.account == PluginGrant::Unasked &&
                     m_saving.keys == PluginGrant::Unasked &&
                     m_saving.state == PluginGrant::Unasked;
    if (!forgotten) {
        m_entries.insert(hash, m_saving);
        m_entry_rows.value(hash)->setSub(rowSub(m_saving));
        return;
    }
    // Hidden, not deleted: the next read deletes it.
    m_entries.remove(hash);
    m_entry_rows.take(hash)->hide();
    m_empty->setVisible(m_entries.isEmpty());
}

} // namespace modal
