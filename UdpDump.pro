TEMPLATE = app
TARGET = UdpDump
QT += core \
    gui \
    network
HEADERS += pcapwrap_lib.h \
    PcapWrap.h \
    udpdump.h
SOURCES += PcapWrap.cpp \
    main.cpp \
    udpdump.cpp
FORMS += udpdump.ui
RESOURCES += 
LIBS += -lpcap
