#ifndef UDPDUMP_H
#define UDPDUMP_H

#include <QtGui/QWidget>
#include <QtCore>
#include "ui_udpdump.h"
#include "PcapWrap.h"

class UdpDump : public QWidget, public Ui::UdpDumpClass
{
    Q_OBJECT

public:
    UdpDump(QWidget *parent = 0);
    ~UdpDump();
    void setData(QString data);

private:
    PcapWrap *wrap;

private slots:
	void process();
};

#endif // UDPDUMP_H
