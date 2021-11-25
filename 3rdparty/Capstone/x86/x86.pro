#-------------------------------------------------
#
# Project created by QtCreator 2019-02-01T10:50:10
#
#-------------------------------------------------

QT       -= core gui

TARGET = capstone
TEMPLATE = lib
CONFIG += staticlib

include(../../../build.pri)

CONFIG(debug, debug|release) {
    TARGET = capstone_x86d
} else {
    TARGET = capstone_x86
}

win32 {
    DEFINES += "WIN32"
}

CONFIG += c++11

DEFINES += "CAPSTONE_HAS_X86"

DEFINES += "CAPSTONE_X86_ATT_DISABLE"
DEFINES += "CAPSTONE_DIET_NO"
#DEFINES += "CAPSTONE_X86_REDUCE"
DEFINES += "CAPSTONE_USE_SYS_DYN_MEM"
DEFINES += "_LIB"

INCLUDEPATH += $$PWD/../src/
DEPENDPATH += $$PWD/../src/

SOURCES += \
    ../src/MCInst.c \
    ../src/MCInstrDesc.c \
    ../src/MCRegisterInfo.c \
    ../src/SStream.c \
    ../src/arch/X86/X86ATTInstPrinter.c \
    ../src/arch/X86/X86Disassembler.c \
    ../src/arch/X86/X86DisassemblerDecoder.c \
    ../src/arch/X86/X86InstPrinterCommon.c \
    ../src/arch/X86/X86IntelInstPrinter.c \
    ../src/arch/X86/X86Mapping.c \
    ../src/arch/X86/X86Module.c \
    ../src/cs.c \
    ../src/utils.c

TARGETLIB_PATH = $$PWD/../

win32-g++ {
    contains(QT_ARCH, i386) {
        DESTDIR=$${TARGETLIB_PATH}/libs/win32-g++
    } else {
        DESTDIR=$${TARGETLIB_PATH}/libs/win64-g++
    }
}
win32-msvc* {
    contains(QMAKE_TARGET.arch, x86_64) {
        DESTDIR=$${TARGETLIB_PATH}/libs/win64-msvc
    } else {
        DESTDIR=$${TARGETLIB_PATH}/libs/win32-msvc
    }
}
unix:!macx {
    BITSIZE = $$system(getconf LONG_BIT)
    if (contains(BITSIZE, 64)) {
        DESTDIR=$${TARGETLIB_PATH}/libs/lin64
    }
    if (contains(BITSIZE, 32)) {
        DESTDIR=$${TARGETLIB_PATH}/libs/lin32
    }
}
unix:macx {
    DESTDIR=$${TARGETLIB_PATH}/libs/mac
}
