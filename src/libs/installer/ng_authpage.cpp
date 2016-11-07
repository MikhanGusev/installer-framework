/******************************************************************************
*
*    Author: Mikhail Gusev, gusevmihs@gmail.com
*    Copyright (C) 2014-2016 NextGIS, info@nextgis.com
*
*    This file is part of the Qt Installer Framework modified for NextGIS
*    Installer project.
*
*    GNU Lesser General Public License Usage
*    This file may be used under the terms of the GNU Lesser
*    General Public License version 2.1 or version 3 as published by the Free
*    Software Foundation and appearing in the file LICENSE.LGPLv21 and
*    LICENSE.LGPLv3 included in the packaging of this file. Please review the
*    following information to ensure the GNU Lesser General Public License
*    requirements will be met: https://www.gnu.org/licenses/lgpl.html and
*    http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
*
*****************************************************************************/

#include "ng_authpage.h"
#include "ngauth/ngaccess.h"

#include"ngauth/simplecrypt.h"

#include <QVBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

#include <QUrl>
#include <QNetworkCookie>
#include <QNetworkReply>

#include <QJsonDocument>
#include <QJsonObject>

#include <QSettings>

using namespace QInstaller;

#define NG_URL_FORGOT "https://my.nextgis.com/password/reset/"
#define NG_URL_REGISTER "https://my.nextgis.com/signup/"

//#define NG_URL_LOGIN "https://my.nextgis.com/login/"
#define NG_URL_LOGIN "https://my.nextgis.com/api/v1/simple_auth/"
#define NG_COOKIE_CSRF "ngid_csrftoken"

#define NG_SETTINGS_LOGIN "login"
#define NG_SETTINGS_PASSWORD "password"

NextgisAuthPage::NextgisAuthPage (PackageManagerCore *core)
    : PackageManagerPage (core)
{
    m_isAuthorized = false;

    //setPixmap(QWizard::WatermarkPixmap, QPixmap());
    setObjectName(QLatin1String("NextgisAuthPage"));
    setColoredTitle(tr("NextGIS authentication"));
    setColoredSubTitle(tr("Enter your NextGIS credentials"));

    m_labLogin = new QLabel(this);
    m_labLogin->setText(tr("Login or E-mail: "));

    m_labPassword = new QLabel(this);
    m_labPassword->setText(tr("Password: "));

    m_eLogin = new QLineEdit(this);

    m_ePassword = new QLineEdit(this);
    m_ePassword->setEchoMode(QLineEdit::Password);

    m_bpAuth = new QPushButton(this);
    m_bpAuth->setText(tr("Authorize"));
    connect(m_bpAuth, SIGNAL(clicked()), this, SLOT(onAuthClicked()));

    m_labInfo = new QLabel(this);
    m_labInfo->setText(tr(""));

    _test_textEdit = new QTextEdit(this);

    m_labForgot = new QLabel(this);
    m_labForgot->setText(QLatin1String("<a href=\"")
                         + QLatin1String(NG_URL_FORGOT)
                         + QLatin1String("\">")
                         + tr("Forgot password?")
                         + QLatin1String("</a>"));
    m_labForgot->setOpenExternalLinks(true);

    m_labGet = new QLabel(this);
    m_labGet->setText(QLatin1String("<a href=\"")
                      + QLatin1String(NG_URL_REGISTER)
                      + QLatin1String("\">")
                      + tr("Register now")
                      + QLatin1String("</a>"));
    m_labGet->setOpenExternalLinks(true);

    QFormLayout *lfAuth = new QFormLayout();
    lfAuth->addRow(m_labLogin, m_eLogin);
    lfAuth->addRow(m_labPassword, m_ePassword);

    QVBoxLayout *lvAll = new QVBoxLayout();
    lvAll->addLayout(lfAuth);
    lvAll->addWidget(m_bpAuth);
    lvAll->addWidget(m_labForgot);
    lvAll->addWidget(m_labGet);
    lvAll->addStretch();
    lvAll->addWidget(m_labInfo);
    lvAll->addWidget(_test_textEdit);

    //QVBoxLayout *lvLinks = new QVBoxLayout();
    //lvLinks->addWidget(m_labForgot);
    //lvLinks->addWidget(m_labGet);
    //lvLinks->addStretch();

    QHBoxLayout *lhMain = new QHBoxLayout(this);
    lhMain->addStretch();
    lhMain->addLayout(lvAll);
    lhMain->addStretch();
    //lhMain->addLayout(lvLinks);

    _test_textEdit->hide();
}


bool NextgisAuthPage::isComplete () const
{
    return m_isAuthorized;
}


void NextgisAuthPage::leaving ()
{
    // TODO: implement the following.
    // Write required NextGIS parameters when leaving this page.

    //packageManagerCore()->setValue(scNgwLogin, login);
    //packageManagerCore()->setValue(scNgwPassword, password);
}


void NextgisAuthPage::onAuthClicked ()
{
    m_labInfo->setText(tr("Connecting ..."));
    m_bpAuth->setEnabled(false);
    m_isAuthorized = false;
    emit completeChanged();

    // Make first (from two) GET request.
    m_baReceived.clear();
    QUrl url;
    url.setUrl(QString::fromUtf8(NG_URL_LOGIN));
    QNetworkRequest request(url);
    m_netReply = NgAccess::manager.get(request);
    QObject::connect(m_netReply, SIGNAL(finished()),
                     this, SLOT(onReplyFinished()));
    QObject::connect(m_netReply, SIGNAL(readyRead()),
                     this, SLOT(onReplyReadyRead()));
}


void NextgisAuthPage::onReplyReadyRead ()
{
    this->_readReply(m_netReply);
}

void NextgisAuthPage::onReply2ReadyRead ()
{
    this->_readReply(m_netReply2);
}


void NextgisAuthPage::onReplyFinished ()
{
    if (m_netReply->error() != QNetworkReply::NoError)
    {
        this->_authFailed(m_netReply);
        return;
    }

    // Get cookie for csrftoken.
    QVariant va = m_netReply->header(QNetworkRequest::SetCookieHeader);
    QString strCsrf = QString::fromUtf8("");
    if (va.isValid())
    {
        QList<QNetworkCookie> cookies = va.value<QList<QNetworkCookie> >();
        foreach (QNetworkCookie cookie, cookies)
        {
            if (QString::fromUtf8(cookie.name())
                    == QString::fromUtf8(NG_COOKIE_CSRF))
            {
                strCsrf = QString::fromUtf8(cookie.value());
                break;
            }
        }
    }
    if (strCsrf == QString::fromUtf8(""))
    {
        this->_authFailed(m_netReply);
        return;
    }

    // Make second (final) POST request if first GET was successful.
    m_baReceived.clear();
    QUrl url;
    url.setUrl(QString::fromUtf8(NG_URL_LOGIN));
    QNetworkRequest request(url);
    QByteArray ba = QString::fromUtf8("username=").toUtf8()
            + m_eLogin->text().toUtf8()
            + QString::fromUtf8("&password=").toUtf8()
            + m_ePassword->text().toUtf8()
            + QString::fromUtf8("&csrfmiddlewaretoken=").toUtf8()
            + strCsrf.toUtf8();
    request.setHeader(QNetworkRequest::ContentTypeHeader,
            QVariant(QString::fromUtf8("application/x-www-form-urlencoded")));
    request.setRawHeader(QString::fromUtf8("Referer").toUtf8(),
                         QString::fromUtf8(NG_URL_LOGIN).toUtf8());
    m_netReply2 = NgAccess::manager.post(request, ba);
    QObject::connect(m_netReply2, SIGNAL(finished()),
                     this, SLOT(onReply2Finished()));
    QObject::connect(m_netReply2, SIGNAL(readyRead()),
                     this, SLOT(onReply2ReadyRead()));

    m_netReply->deleteLater();
}


void NextgisAuthPage::onReply2Finished ()
{
    if (m_netReply2->error() != QNetworkReply::NoError)
    {
        this->_authFailed(m_netReply2);
        return;
    }

    // Parse reply for authentication errors.
    _test_textEdit->setText(QString::fromUtf8(m_baReceived));
    QJsonDocument jDoc = QJsonDocument::fromJson(m_baReceived);
    if (jDoc.isNull())
    {
        this->_authFailed(m_netReply2);
        return;
    }
    QJsonObject jObj = jDoc.object();
    if (jObj.value(QString::fromUtf8("status")).toString()
                   != QString::fromUtf8("success"))
    {
        this->_authFailed(m_netReply2);
        m_labInfo->setText(tr("Authorization failed."
                              "\nLogin and/or password is incorrect"));
        return;
    }

    // Save login and password to the settings file.
    SimpleCrypt crypto;
    crypto.setKey(Q_UINT64_C(0x0c2ad4a4acb9f023)); // TEMP
    QString loginToSave = crypto.encryptToString(
                QString::fromUtf8(m_eLogin->text().toUtf8().data()));
    QString passToSave = crypto.encryptToString(
                QString::fromUtf8(m_ePassword->text().toUtf8().data()));
    QSettings settings(QSettings::IniFormat, QSettings::UserScope,
                       QString::fromUtf8("NextGIS"),
                       QString::fromUtf8("Common"));
    settings.setValue(QString::fromUtf8(NG_SETTINGS_LOGIN),loginToSave);
    settings.setValue(QString::fromUtf8(NG_SETTINGS_PASSWORD),passToSave);

    // Show success info.
    // TODO: show required information to user.
    m_labInfo->setText(tr("Authorization successful."
                          "\nClick Next to continue installation"));
    m_bpAuth->setEnabled(true);
    m_isAuthorized = true;
    emit completeChanged();
    m_netReply2->deleteLater();
}


void NextgisAuthPage::_readReply (QNetworkReply *reply)
{
    QByteArray ba;
    ba = reply->readAll();
    m_baReceived += ba;
}

void NextgisAuthPage::_authFailed (QNetworkReply *replyToDelete)
{
    //_test_textEdit->setText(QString::fromUtf8(replyToDelete->errorString().toUtf8().data()));
    _test_textEdit->setText(QString::fromUtf8(m_baReceived));

    // TODO: show error info and suggested actions for user.
    m_labInfo->setText(tr("Error connecting to server"));
    m_bpAuth->setEnabled(true);
    m_isAuthorized = false;
    emit completeChanged();
    replyToDelete->deleteLater();
}

