/**************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: http://www.qt.io/licensing/
**
** This file is part of the Qt Installer Framework.
**
** $QT_BEGIN_LICENSE:LGPL21$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see http://www.qt.io/terms-conditions. For further
** information use the contact form at http://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** As a special exception, The Qt Company gives you certain additional
** rights. These rights are described in The Qt Company LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** $QT_END_LICENSE$
**
**************************************************************************/

#include "uninstallercalculator.h"

#include "component.h"
#include "packagemanagercore.h"
#include "globals.h"

#include <QDebug>

namespace QInstaller {

UninstallerCalculator::UninstallerCalculator(const QList<Component *> &installedComponents)
    : m_installedComponents(installedComponents)
{
}

QSet<Component *> UninstallerCalculator::componentsToUninstall() const
{
    return m_componentsToUninstall;
}

void UninstallerCalculator::appendComponentToUninstall(Component *component)
{
    if (!component)
        return;

    if (!component->isInstalled())
        return;

    PackageManagerCore *core = component->packageManagerCore();
    // remove all already resolved dependees
    QSet<Component *> dependees = core->dependees(component).toSet()
            .subtract(m_componentsToUninstall);

    foreach (Component *dependee, dependees)
        appendComponentToUninstall(dependee);

    m_componentsToUninstall.insert(component);
}

void UninstallerCalculator::appendComponentsToUninstall(const QList<Component*> &components)
{
    foreach (Component *component, components)
        appendComponentToUninstall(component);

    QList<Component*> autoDependOnList;
    // All regular dependees are resolved. Now we are looking for auto depend on components.
    foreach (Component *component, m_installedComponents) {
        // If a components is installed and not yet scheduled for un-installation, check for auto depend.
        if (component->isInstalled() && !m_componentsToUninstall.contains(component)) {
            QStringList autoDependencies = component->autoDependencies();
            if (autoDependencies.isEmpty())
                continue;

            // This code needs to be enabled once the scripts use isInstalled, installationRequested and
            // uninstallationRequested...
            if (autoDependencies.first().compare(scScript, Qt::CaseInsensitive) == 0) {
                //QScriptValue valueFromScript;
                //try {
                //    valueFromScript = callScriptMethod(QLatin1String("isAutoDependOn"));
                //} catch (const Error &error) {
                //    // keep the component, should do no harm
                //    continue;
                //}

                //if (valueFromScript.isValid() && !valueFromScript.toBool())
                //    autoDependOnList.append(component);
                continue;
            }

            foreach (Component *c, m_installedComponents) {
                const QString replaces = c->value(scReplaces);
                const QStringList possibleNames = replaces.split(QInstaller::commaRegExp(),
                                                                 QString::SkipEmptyParts) << c->name();
                foreach (const QString &possibleName, possibleNames)
                    autoDependencies.removeAll(possibleName);
            }

            // A component requested auto installation, keep it to resolve their dependencies as well.
            if (!autoDependencies.isEmpty())
                autoDependOnList.append(component);
        }
    }

    if (!autoDependOnList.isEmpty())
        appendComponentsToUninstall(autoDependOnList);
}

} // namespace QInstaller
