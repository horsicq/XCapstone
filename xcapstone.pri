INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xcapstone.h

SOURCES += \
    $$PWD/xcapstone.cpp

!contains(XCONFIG, capstone) {
    XCONFIG += capstone
    include(3rdparty/Capstone/QCapstone_x86.pri)
}
