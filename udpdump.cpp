#include <QtCore>
#include "udpdump.h"

UdpDump::UdpDump(QWidget *parent)
    : QWidget(parent)
{
	setupUi(this);

	wrap = new PcapWrap;

	connect(btnCapture,       SIGNAL(clicked()),   this,   SLOT(process()));
}

UdpDump::~UdpDump()
{
	wrap->close();
	delete wrap;
}


void UdpDump::setData(QString data)
{
	txtContent->setPlainText(data);
}



void UdpDump::process()
{
	 wrap->setWidget(this);
	 wrap->process();
}

