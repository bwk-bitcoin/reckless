#pragma once

#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

// Frozen IPlugin declarations from de26556 through ABI 11, independent of the current SDK.
class IModule;

class IPlugin {
public:
    virtual ~IPlugin() = default;
    [[nodiscard]] virtual QMap<QString, QString> meta() const = 0;
    [[nodiscard]] virtual QList<IModule *> modules() const = 0;
};

#ifdef RECKLESS_ABI11_FIXTURE
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/11.0"
#elif defined(RECKLESS_ABI10_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/10.0"
#elif defined(RECKLESS_ABI9_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/9.0"
#elif defined(RECKLESS_ABI8_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/8.0"
#elif defined(RECKLESS_ABI7_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/7.0"
#elif defined(RECKLESS_ABI6_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/6.0"
#elif defined(RECKLESS_ABI5_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/5.0"
#elif defined(RECKLESS_ABI4_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/4.0"
#elif defined(RECKLESS_ABI3_FIXTURE)
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/3.0"
#else
#define RECKLESS_IPlugin_IID "dev.reckless.IPlugin/2.0"
#endif
Q_DECLARE_INTERFACE(IPlugin, RECKLESS_IPlugin_IID)
