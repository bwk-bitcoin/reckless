#pragma once

#include "interfaces/enums.h"
#include "theme/Palette.h"

#include <QList>
#include <QStringList>
#include <QWidget>

class QLabel;

namespace catalog {

class Label;

// The step trail atop a wizard modal, centred: numbered dots at a fixed pitch,
// with rules filling the remaining space;
// done steps show a check, the current one is accent and bold, later ones muted.
// More steps than fit (ws-plaude/silent#129) show a window around the current one:
// the first and last steps, the current one and its neighbours, every hidden run
// between them one ellipsis. Display only: the modal's Back and Continue move between
// steps.
class WizardSteps : public QWidget {
    Q_OBJECT

public:
    explicit WizardSteps(const QStringList &steps, QWidget *parent = nullptr);
    void setCurrent(int index);
    // A step's outcome (ws-plaude/silent#133): Failed a cross in the error colour,
    // Skipped a dash, Passed the check; Pending follows the current index.
    void setStepState(int index, plugin::StepState state);
    [[nodiscard]] auto stepState(int index) const -> plugin::StepState;
    static auto qss(const Palette &p) -> QString;

protected:
    void refresh();

private:
    // Whether step `index` shows: every step when they all fit.
    [[nodiscard]] auto shown(int index) const -> bool;

    // One per step: its dot, name and the rule after it.
    QList<QWidget *> m_steps;
    // The ellipsis after each step but the last, shown before a hidden run.
    QList<QLabel *> m_gaps;
    QList<plugin::StepState> m_states;
    QList<QLabel *> m_dots;
    QList<Label *> m_names;
    // The rule before each step but the first.
    QList<QWidget *> m_rules;
    int m_current = 0;
};

} // namespace catalog
