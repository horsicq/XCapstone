#-------------------------------------------------
#
# Project created by QtCreator 2019-02-01T10:50:10
#
#-------------------------------------------------

QT       -= core gui

TARGET = capstone
TEMPLATE = lib
CONFIG += staticlib

include(../../build.pri)

CONFIG(debug, debug|release) {
    TARGET = capstoned
} else {
    TARGET = capstone
}

win32 {
    DEFINES += "WIN32"
}

DEFINES += "CAPSTONE_HAS_ARM"
DEFINES += "CAPSTONE_HAS_ARM64"
DEFINES += "CAPSTONE_HAS_EVM"
DEFINES += "CAPSTONE_HAS_M68K"
DEFINES += "CAPSTONE_HAS_M680X"
DEFINES += "CAPSTONE_HAS_MIPS"
DEFINES += "CAPSTONE_HAS_POWERPC"
DEFINES += "CAPSTONE_HAS_SPARC"
DEFINES += "CAPSTONE_HAS_SYSZ"
DEFINES += "CAPSTONE_HAS_TMS320C64X"
DEFINES += "CAPSTONE_HAS_X86"
DEFINES += "CAPSTONE_HAS_XCORE"
DEFINES += "CAPSTONE_X86_ATT_DISABLE_NO"
DEFINES += "CAPSTONE_DIET_NO"
DEFINES += "CAPSTONE_X86_REDUCE_NO"
DEFINES += "CAPSTONE_X86_REDUCE_NO"
DEFINES += "CAPSTONE_USE_SYS_DYN_MEM"
DEFINES += "_LIB"

INCLUDEPATH += $$PWD/src/
DEPENDPATH += $$PWD/src/

SOURCES += \
    $$PWD/src/cs.c \
    $$PWD/src/arch/X86/X86ATTInstPrinter.c \
    $$PWD/src/arch/X86/X86Disassembler.c \
    $$PWD/src/arch/X86/X86DisassemblerDecoder.c \
    $$PWD/src/arch/X86/X86IntelInstPrinter.c \
    $$PWD/src/arch/X86/X86Mapping.c \
    $$PWD/src/arch/X86/X86Module.c \
    $$PWD/src/MCInst.c \
    $$PWD/src/SStream.c \
    $$PWD/src/MCRegisterInfo.c \
    $$PWD/src/utils.c \
    src/arch/AArch64/AArch64BaseInfo.c \
    src/arch/AArch64/AArch64Disassembler.c \
    src/arch/AArch64/AArch64InstPrinter.c \
    src/arch/AArch64/AArch64Mapping.c \
    src/arch/AArch64/AArch64Module.c \
    src/arch/ARM/ARMDisassembler.c \
    src/arch/ARM/ARMInstPrinter.c \
    src/arch/ARM/ARMMapping.c \
    src/arch/ARM/ARMModule.c \
    src/arch/EVM/EVMDisassembler.c \
    src/arch/EVM/EVMInstPrinter.c \
    src/arch/EVM/EVMMapping.c \
    src/arch/EVM/EVMModule.c \
    src/arch/M680X/M680XDisassembler.c \
    src/arch/M680X/M680XInstPrinter.c \
    src/arch/M680X/M680XModule.c \
    src/arch/M68K/M68KDisassembler.c \
    src/arch/M68K/M68KInstPrinter.c \
    src/arch/M68K/M68KModule.c \
    src/arch/Mips/MipsDisassembler.c \
    src/arch/Mips/MipsInstPrinter.c \
    src/arch/Mips/MipsMapping.c \
    src/arch/Mips/MipsModule.c \
    src/arch/PowerPC/PPCDisassembler.c \
    src/arch/PowerPC/PPCInstPrinter.c \
    src/arch/PowerPC/PPCMapping.c \
    src/arch/PowerPC/PPCModule.c \
    src/arch/Sparc/SparcDisassembler.c \
    src/arch/Sparc/SparcInstPrinter.c \
    src/arch/Sparc/SparcMapping.c \
    src/arch/Sparc/SparcModule.c \
    src/arch/SystemZ/SystemZDisassembler.c \
    src/arch/SystemZ/SystemZInstPrinter.c \
    src/arch/SystemZ/SystemZMCTargetDesc.c \
    src/arch/SystemZ/SystemZMapping.c \
    src/arch/SystemZ/SystemZModule.c \
    src/arch/TMS320C64x/TMS320C64xDisassembler.c \
    src/arch/TMS320C64x/TMS320C64xInstPrinter.c \
    src/arch/TMS320C64x/TMS320C64xMapping.c \
    src/arch/TMS320C64x/TMS320C64xModule.c \
    src/arch/XCore/XCoreDisassembler.c \
    src/arch/XCore/XCoreInstPrinter.c \
    src/arch/XCore/XCoreMapping.c \
    src/arch/XCore/XCoreModule.c

TARGETLIB_PATH = $$PWD

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
