#pragma once

#include <QCoreApplication>
#include <QString>

// Plugin-side translation macros.
//
// Define RECKLESS_PLUGIN_ID as a string literal before including this header:
//   #define RECKLESS_PLUGIN_ID "example"
//   #include <interfaces/tr.h>
//
// The host loads plugin catalogs from:
//   ~/.reckless/plugins/<id>/i18n/reckless_<locale>.lang
// and expects keys to be prefixed with the same <id>. namespace.
// These macros inject that prefix at compile time so plugin call sites remain:
//   TR("my-key") / TRN("my-key", n)

#ifndef RECKLESS_PLUGIN_ID
#ifdef __clang_analyzer__
// clang-tidy/clangd parse this header on its own, without the build-time define.
// Supply a placeholder so the SDK header analyzes cleanly; real plugin builds
// (which do not define __clang_analyzer__) still hit the #error below.
#define RECKLESS_PLUGIN_ID "clang-tidy"
#else
#error "RECKLESS_PLUGIN_ID must be defined as a string literal before including <interfaces/tr.h>"
#endif
#endif

#define RECKLESS_PLUGIN_TR_PREFIX RECKLESS_PLUGIN_ID "."

#define TR(id) ([&]() -> QString { return qtTrId(RECKLESS_PLUGIN_TR_PREFIX id); }())

#define TRN(id, n) ([&]() -> QString { return qtTrId(RECKLESS_PLUGIN_TR_PREFIX id, n); }())
