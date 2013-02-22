/********************************************************************************
** Form generated from reading UI file 'udpdump.ui'
**
** Created: Thu Jun 23 16:10:56 2011
**      by: Qt User Interface Compiler version 4.7.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_UDPDUMP_H
#define UI_UDPDUMP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QHeaderView>
#include <QtGui/QPlainTextEdit>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_UdpDumpClass
{
public:
    QPlainTextEdit *txtContent;
    QPushButton *btnCapture;

    void setupUi(QWidget *UdpDumpClass)
    {
        if (UdpDumpClass->objectName().isEmpty())
            UdpDumpClass->setObjectName(QString::fromUtf8("UdpDumpClass"));
        UdpDumpClass->resize(970, 588);
        txtContent = new QPlainTextEdit(UdpDumpClass);
        txtContent->setObjectName(QString::fromUtf8("txtContent"));
        txtContent->setGeometry(QRect(10, 50, 951, 521));
        btnCapture = new QPushButton(UdpDumpClass);
        btnCapture->setObjectName(QString::fromUtf8("btnCapture"));
        btnCapture->setGeometry(QRect(850, 10, 88, 27));

        retranslateUi(UdpDumpClass);

        QMetaObject::connectSlotsByName(UdpDumpClass);
    } // setupUi

    void retranslateUi(QWidget *UdpDumpClass)
    {
        UdpDumpClass->setWindowTitle(QApplication::translate("UdpDumpClass", "UdpDump", 0, QApplication::UnicodeUTF8));
        btnCapture->setText(QApplication::translate("UdpDumpClass", "Capture", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class UdpDumpClass: public Ui_UdpDumpClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_UDPDUMP_H
