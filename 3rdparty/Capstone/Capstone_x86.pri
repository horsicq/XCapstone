INCLUDEPATH += $$PWD/src
DEPENDPATH += $$PWD/src
INCLUDEPATH += $$PWD/src/include
DEPENDPATH += $$PWD/src/include

# TODO ARM
win32-g++ {
    contains(QT_ARCH, i386) {
        LIBS += $$PWD/libs/win32-g++/libcapstone_x86.a
    } else {
        LIBS += $$PWD/libs/win64-g++/libcapstone_x86.a
    }
}

win32-msvc* {
    contains(QMAKE_TARGET.arch, x86_64) {
        LIBS += $$PWD/libs/win64-msvc/capstone_x86.lib
    } else {
        LIBS += $$PWD/libs/win32-msvc/capstone_x86.lib
    }
}
# TODO ARM
unix:!macx {
    BITSIZE = $$system(getconf LONG_BIT)
    if (contains(BITSIZE, 64)) {
        LIBS +=  $$PWD/libs/lin64/libcapstone_x86.a
    }
    if (contains(BITSIZE, 32)) {
        LIBS +=  $$PWD/libs/lin32/libcapstone_x86.a
    }
}
# TODO ARM
unix:macx {
    LIBS +=  $$PWD/libs/mac/libcapstone_x86.a
}
