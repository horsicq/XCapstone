INCLUDEPATH += $$PWD/src
DEPENDPATH += $$PWD/src
INCLUDEPATH += $$PWD/src/include
DEPENDPATH += $$PWD/src/include

win32-g++ {
    contains(QT_ARCH, i386) {
        LIBS += $$PWD/libs/win32-g++/libcapstone.a
    } else {
        LIBS += $$PWD/libs/win64-g++/libcapstone.a
    }
}
win32-msvc* {
    contains(QMAKE_TARGET.arch, x86_64) {
        LIBS += $$PWD/libs/win64-msvc/capstone.lib
    } else {
        LIBS += $$PWD/libs/win32-msvc/capstone.lib
    }
}
unix:!macx {
    BITSIZE = $$system(getconf LONG_BIT)
    if (contains(BITSIZE, 64)) {
        LIBS +=  $$PWD/libs/lin64/libcapstone.a
    }
    if (contains(BITSIZE, 32)) {
        LIBS +=  $$PWD/libs/lin32/libcapstone.a
    }
}
unix:macx {
    LIBS +=  $$PWD/libs/mac/libcapstone.a
}
