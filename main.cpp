#include "udpdump.h"

#include <QtGui>
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    UdpDump w;
    w.show();

    return a.exec();
}
