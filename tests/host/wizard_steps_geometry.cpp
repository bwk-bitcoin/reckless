#include "catalog/display/Label.h"
#include "catalog/display/WizardSteps.h"
#include "i18n/I18nManager.h"
#include "i18n/Tr.h"
#include "theme/Theme.h"

#include <QApplication>
#include <QDebug>
#include <QLayout>
#include <QStringList>
#include <QWidget>
#include <Qontrol>
#include <algorithm>
#include <cstdlib>

namespace {

void check(bool passed, const QString &context) {
    if (!passed) {
        qCritical().noquote() << context;
        std::exit(EXIT_FAILURE);
    }
}

void settle(QWidget &widget) {
    for (int pass = 0; pass < 4; ++pass) {
        for (auto *layout : widget.findChildren<QLayout *>()) {
            layout->activate();
        }
        QApplication::processEvents();
    }
}

void checkTrail(const QStringList &labels, const QString &context, int width) {
    QWidget window;
    auto *trail = new catalog::WizardSteps(labels);
    (new qontrol::Column)->margins(0)->push(trail)->pushSpacer()->into(&window);
    window.resize(width, 768);
    window.show();
    settle(window);
    check(window.width() == width, context + ": trail widened the window");
    check(trail->minimumSizeHint().width() <= 695, context + ": minimum width exceeds 695");
    auto names = trail->findChildren<catalog::Label *>();
    QList<QLabel *> dots;
    QList<QWidget *> rules;
    for (auto *child : trail->findChildren<QWidget *>()) {
        if (child->property("class") == "wizard-dot") {
            dots.append(qobject_cast<QLabel *>(child));
        } else if (child->property("class") == "wizard-rule") {
            rules.append(child);
        }
    }
    check(dots.size() == labels.size(), context + ": wrong number of dots");
    check(rules.size() == std::max(0, int(labels.size()) - 1), context + ": wrong rule count");
    QList<QPoint> positions;
    for (auto *dot : dots) {
        positions.append(dot->mapTo(trail, QPoint(10, 10)));
    }
    auto originalSize = trail->sizeHint();
    for (int current = 0; current <= labels.size(); ++current) {
        trail->setCurrent(current);
        settle(window);
        check(trail->sizeHint() == originalSize, context + ": active state changed size hint");
        for (int i = 0; i < dots.size(); ++i) {
            auto point = dots.at(i)->mapTo(trail, QPoint(10, 10));
            check(point == positions.at(i),
                  context + ": active state moved dot " + QString::number(i));
            check(names.at(i)->font().weight() == (i == current ? font::DEMIBOLD : QFont::Normal),
                  context + ": incorrect label weight");
            auto expectedState = QStringLiteral("next");
            if (i < current) {
                expectedState = QStringLiteral("done");
            } else if (i == current) {
                expectedState = QStringLiteral("current");
            }
            check(dots.at(i)->property("state").toString() == expectedState,
                  context + ": incorrect dot state");
            auto *name = names.at(i);
            check(!name->wordWrap() || name->height() >= name->heightForWidth(name->width()),
                  context + ": wrapped text clipped vertically");
            auto nameLeft = name->mapTo(trail, QPoint()).x();
            auto nameEnd = nameLeft + name->width();
            check(nameLeft >= point.x() + 15, context + ": label overlaps dot");
            check(nameEnd <= trail->width(), context + ": last label exceeds header");
            if (i + 1 < dots.size()) {
                auto next = dots.at(i + 1)->mapTo(trail, QPoint(10, 10));
                check(next.x() - point.x() == 120 && next.y() == point.y(),
                      context + ": expected aligned 120px number pitch");
                auto *rule = rules.at(i);
                auto ruleLeft = rule->mapTo(trail, QPoint()).x();
                check(ruleLeft == nameEnd + 5, context + ": rule must follow label with 5px gap");
                check(ruleLeft + rule->width() == next.x() - 15,
                      context + ": rule must fill remaining span up to 5px before next dot");
                check(rule->property("done").toBool() == (i + 1 <= current),
                      context + ": incorrect rule state");
            }
        }
        if (!dots.empty()) {
            auto left = positions.first().x() - 10;
            auto right = names.last()->mapTo(trail, QPoint()).x() + names.last()->width();
            check(std::abs(left - (trail->width() - right)) <= 1,
                  context + ": whole trail is not centred");
        }
    }
    qInfo() << context << "width" << width << "number centres" << positions;
}

// ws-plaude/silent#129: more steps than fit show a window around the current one, the
// first and last kept, each hidden run one ellipsis, inside the header's width.
void checkWindowed(int count, int width) {
    QStringList labels;
    for (int i = 0; i < count; ++i) {
        labels.append(QStringLiteral("Step %1").arg(i + 1));
    }
    QWidget window;
    auto *trail = new catalog::WizardSteps(labels);
    (new qontrol::Column)->margins(0)->push(trail)->pushSpacer()->into(&window);
    window.resize(width, 768);
    window.show();
    QList<QLabel *> dots;
    QList<QLabel *> gaps;
    for (auto *child : trail->findChildren<QLabel *>()) {
        if (child->property("class") == "wizard-dot") {
            dots.append(child);
        } else if (child->property("class") == "wizard-gap") {
            gaps.append(child);
        }
    }
    check(dots.size() == count, "windowed: one dot per step");
    auto context = QStringLiteral("windowed %1 steps at %2").arg(count).arg(width);
    // Forwards, then back down as a plugin's Back does.
    QList<int> currents{0, 1, count / 2, count - 2, count - 1, count / 2, 1, 0};
    for (auto current : currents) {
        trail->setCurrent(current);
        settle(window);
        auto here = context + QStringLiteral(" current %1").arg(current);
        QList<int> visible;
        for (int i = 0; i < count; ++i) {
            if (dots.at(i)->isVisible()) {
                visible.append(i);
            }
        }
        QList<int> expected;
        for (int i = 0; i < count; ++i) {
            if (i == 0 || i == count - 1 || std::abs(i - current) <= 1) {
                expected.append(i);
            }
        }
        check(visible == expected, here + ": shows the first, last, current and its neighbours");
        int runs = 0;
        for (int k = 1; k < visible.size(); ++k) {
            runs += visible.at(k) - visible.at(k - 1) > 1 ? 1 : 0;
        }
        auto shownGaps = std::count_if(gaps.begin(), gaps.end(),
                                       [](const QLabel *gap) { return gap->isVisible(); });
        check(shownGaps == runs, here + ": one ellipsis per hidden run");
        for (auto i : visible) {
            check(i < current || dots.at(i)->text() == QString::number(i + 1),
                  here + ": a step keeps its real number");
            check(dots.at(i)->property("state").toString() == (i < current    ? "done"
                                                               : i == current ? "current"
                                                                              : "next"),
                  here + ": incorrect dot state");
        }
        for (int k = 1; k < visible.size(); ++k) {
            auto left = dots.at(visible.at(k - 1))->mapTo(trail, QPoint()).x();
            auto right = dots.at(visible.at(k))->mapTo(trail, QPoint()).x();
            check(right - left >= 120, here + ": shown steps do not overlap");
        }
        check(trail->minimumSizeHint().width() <= 695, here + ": minimum width exceeds 695");
        check(window.width() == width, here + ": trail widened the window");
    }
}

// ws-plaude/silent#133: a step's own outcome, drawn over the current index's done
// steps; a hidden run holding a failed step shows its ellipsis in the error tone.
void checkStates() {
    QStringList labels;
    for (int i = 0; i < 10; ++i) {
        labels.append(QStringLiteral("Step %1").arg(i + 1));
    }
    QWidget window;
    auto *trail = new catalog::WizardSteps(labels);
    (new qontrol::Column)->margins(0)->push(trail)->pushSpacer()->into(&window);
    window.resize(1024, 768);
    window.show();
    QList<QLabel *> dots;
    for (auto *child : trail->findChildren<QLabel *>()) {
        if (child->property("class") == "wizard-dot") {
            dots.append(child);
        }
    }
    auto state = [&dots](int index) { return dots.at(index)->property("state").toString(); };
    trail->setCurrent(5);
    settle(window);
    check(state(4) == "done" && state(5) == "current" && state(6) == "next",
          "with no state set, the trail follows the current index as before");
    trail->setStepState(2, plugin::StepState::Failed);
    trail->setStepState(3, plugin::StepState::Skipped);
    trail->setStepState(7, plugin::StepState::Passed);
    trail->setStepState(5, plugin::StepState::Failed);
    trail->setStepState(42, plugin::StepState::Failed);
    trail->setStepState(1, static_cast<plugin::StepState>(9));
    settle(window);
    check(state(2) == "failed" && dots.at(2)->text().isEmpty(), "a failed step shows its cross");
    check(state(3) == "skipped", "a skipped step shows apart from done and next");
    check(state(7) == "done", "a passed step after the current one shows its check");
    check(state(1) == "done", "an unknown state is ignored");
    check(state(5) == "failed" && dots.at(5)->property("current").toBool(),
          "the current step keeps its ring whatever its state");
    auto names = trail->findChildren<catalog::Label *>();
    check(names.at(2)->property("tone").toString() == QStringLiteral("error"),
          "a failed step's name is in the error tone");
    trail->setStepState(2, plugin::StepState::Pending);
    settle(window);
    check(state(2) == "done", "back to Pending, a step follows the current index again");

    // Forty steps on the twentieth, step 11 failed: the ellipsis before its run warns.
    QStringList forty;
    for (int i = 0; i < 40; ++i) {
        forty.append(QStringLiteral("Step %1").arg(i + 1));
    }
    QWidget wide;
    auto *windowed = new catalog::WizardSteps(forty);
    (new qontrol::Column)->margins(0)->push(windowed)->pushSpacer()->into(&wide);
    wide.resize(1024, 768);
    wide.show();
    windowed->setCurrent(19);
    windowed->setStepState(10, plugin::StepState::Failed);
    windowed->setStepState(30, plugin::StepState::Skipped);
    settle(wide);
    QList<QLabel *> gaps;
    for (auto *child : windowed->findChildren<QLabel *>()) {
        if (child->property("class") == "wizard-gap" && child->isVisible()) {
            gaps.append(child);
        }
    }
    check(gaps.size() == 2, "two hidden runs, two ellipses");
    check(gaps.at(0)->property("failed").toBool() && !gaps.at(1)->property("failed").toBool(),
          "the ellipsis of the run holding the failed step is in the error tone, the other not");
    windowed->setCurrent(10);
    settle(wide);
    for (auto *child : windowed->findChildren<QLabel *>()) {
        if (child->property("class") == "wizard-gap" && child->isVisible()) {
            check(!child->property("failed").toBool(),
                  "once the failed step shows, no ellipsis warns of it");
        }
    }
}

} // namespace

namespace smoke {

// The trail's geometry in every locale and width (host_smoke --wizard-steps).
void wizardStepsGeometrySmoke() {
    Theme::get()->apply();
    for (auto width : {695, 698, 700, 702, 720, 1024}) {
        for (const auto &locale : {"en", "de", "es", "fr", "it", "pt"}) {
            check(i18n::I18nManager::get()->applyLocale(locale, false), "Failed to load locale");
            checkTrail({TR("musig-step-paths"), TR("musig-step-xpubs"), TR("musig-step-review"),
                        TR("musig-step-register"), TR("musig-step-verify"),
                        TR("musig-step-electrum")},
                       QString(locale) + " create", width);
            checkTrail({TR("musig-sign-step-nonces"), TR("musig-sign-step-partial")},
                       QString(locale) + " sign", width);
        }
        checkTrail({"Ausgabepfade", "Erweiterte öffentliche Schlüssel", "Überprüfen",
                    "Registrieren", "Adressen verifizieren", "Electrum-Verbindung"},
                   "long German labels", width);
        checkTrail(
            {"A", "A much longer label", QString(160, 'W'), "短い", "署名を確認してください", "Z"},
            "mixed lengths and unbroken text", width);
        checkTrail({QString(160, 'W'), QString(160, 'W'), QString(160, 'W'), QString(160, 'W'),
                    QString(160, 'W'), QString(160, 'W')},
                   "maximum label widths", width);
        checkTrail({}, "empty", width);
        checkTrail({"Only one step"}, "single", width);
        checkWindowed(7, width);
        checkWindowed(40, width);
        checkWindowed(60, width);
    }
    checkStates();
    check(i18n::I18nManager::get()->applyLocale("en", false), "Failed to restore locale");
    qInfo() << "WizardSteps geometry checks passed";
}

} // namespace smoke
