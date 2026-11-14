#include <QGuiApplication>
#include <QObject>
#include <QSvgRenderer>
#include <QWidget>
#include <Qontrol>

namespace {

#ifdef __has_cpp_attribute
#if __has_cpp_attribute(gnu::used)
#define RECKLESS_USED [[gnu::used]]
#endif
#endif

#ifndef RECKLESS_USED
#if defined(__GNUC__) || defined(__clang__)
#define RECKLESS_USED __attribute__((used))
#else
#define RECKLESS_USED
#endif
#endif

// Keep concrete Qt/qontrol ABI symbols alive so --export-dynamic can publish
// the host-supported plugin surface even with -O2/--gc-sections.
RECKLESS_USED const void *const ANCHORS[] = {
    static_cast<const void *>(&QObject::staticMetaObject),
    static_cast<const void *>(&QGuiApplication::staticMetaObject),
    static_cast<const void *>(&QWidget::staticMetaObject),
    static_cast<const void *>(&QSvgRenderer::staticMetaObject),
    static_cast<const void *>(&qontrol::Window::staticMetaObject),
    static_cast<const void *>(&qontrol::Screen::staticMetaObject),
    static_cast<const void *>(&qontrol::Modal::staticMetaObject),
    static_cast<const void *>(&qontrol::Row::staticMetaObject),
    static_cast<const void *>(&qontrol::Column::staticMetaObject),
    static_cast<const void *>(&qontrol::Panel::staticMetaObject),
    static_cast<const void *>(&qontrol::widgets::ToggleSwitch::staticMetaObject),
};

#undef RECKLESS_USED

} // namespace
