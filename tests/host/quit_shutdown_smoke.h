#pragma once

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QMap>
#include <QObject>
#include <QPointer>
#include <QString>
#include <cstdint>
#include <interfaces/module.h>
#include <interfaces/storage.h>

namespace smoke {

enum class QuitBehavior : std::uint8_t {
    // Saves shutdown.txt while it shuts down and answers once that write is answered.
    SaveOnShutdown,
    // Never answers shutdown.
    Stuck,
    // Saves quit.txt on aboutToQuit and answers shutdown at once.
    SaveOnQuit,
};

class QuitModule final : public IModule {
    Q_OBJECT

public:
    QuitModule(QString id, QuitBehavior behavior, QObject *parent = nullptr);

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override;
    auto list() -> ReqId override;
    auto autoStart() -> ReqId override;
    void startInstance(const QString &id) override;
    void shutdown(ReqId req_id) override;

    // Writes go below `path` in the storage `handle`.
    void prepare(IStorage *storage, const QString &handle, const QString &path);
    [[nodiscard]] auto shutdownCalls() const -> int;
    [[nodiscard]] auto answers() const -> const QHash<QString, QJsonObject> &;

public slots:
    void onAboutToQuit();
    void onCompleted(const QByteArray &message);

protected:
    void write(const QString &id, const QString &name);

private:
    QString m_id;
    QuitBehavior m_behavior;
    QPointer<IStorage> m_storage;
    QString m_handle;
    QString m_path;
    int m_shutdown_calls = 0;
    ReqId m_shutdown_req = 0;
    ReqId m_next = 0;
    QHash<QString, QJsonObject> m_answers;
};

class QuitPlugin final : public QObject, public IPlugin {
    Q_OBJECT
    Q_INTERFACES(IPlugin)

public:
    // The storage plugin holds one SaveOnQuit module, the other a SaveOnShutdown and a
    // Stuck one.
    explicit QuitPlugin(bool storage);

    [[nodiscard]] auto meta() const -> QMap<QString, QString> override;
    [[nodiscard]] auto modules() const -> QList<IModule *> override;
    [[nodiscard]] auto saver() const -> QuitModule *;
    [[nodiscard]] auto stuck() const -> QuitModule *;

private:
    QuitModule *m_saver = nullptr;
    QuitModule *m_stuck = nullptr;
};

// ws-plaude/silent#102: the quit path of main() shuts every module down, within its bound.
void quitShutdownSmoke();
// ws-plaude/silent#103: it also answers the storage writes requested on aboutToQuit, after
// every module answered its shutdown.
void quitStorageSmoke();

} // namespace smoke
