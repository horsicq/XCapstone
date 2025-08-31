/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xcapstone.h"

#if defined(_MSC_VER)
#if _MSC_VER > 1800
#pragma comment(lib, "legacy_stdio_definitions.lib")  // vsprintf // TODO Check !!!
#endif
#endif

XCapstone::XCapstone(QObject *pParent) : QObject(pParent)
{
}

bool XCapstone::isModeValid(XBinary::DM disasmMode)
{
    bool bResult = false;

    if ((disasmMode == XBinary::DM_X86_16) || (disasmMode == XBinary::DM_X86_32) || (disasmMode == XBinary::DM_X86_64) || (disasmMode == XBinary::DM_ARM_LE) ||
        (disasmMode == XBinary::DM_ARM_BE) || (disasmMode == XBinary::DM_AARCH64_LE) || (disasmMode == XBinary::DM_AARCH64_BE) || (disasmMode == XBinary::DM_CORTEXM) ||
        (disasmMode == XBinary::DM_THUMB_LE) || (disasmMode == XBinary::DM_THUMB_BE) || (disasmMode == XBinary::DM_MIPS_LE) || (disasmMode == XBinary::DM_MIPS_BE) ||
        (disasmMode == XBinary::DM_MIPS64_LE) || (disasmMode == XBinary::DM_MIPS64_BE) || (disasmMode == XBinary::DM_PPC_LE) || (disasmMode == XBinary::DM_PPC_BE) ||
        (disasmMode == XBinary::DM_PPC64_LE) || (disasmMode == XBinary::DM_PPC64_BE) || (disasmMode == XBinary::DM_SPARC) || (disasmMode == XBinary::DM_SPARCV9) ||
        (disasmMode == XBinary::DM_S390X) || (disasmMode == XBinary::DM_XCORE) || (disasmMode == XBinary::DM_M68K) || (disasmMode == XBinary::DM_M68K00) ||
        (disasmMode == XBinary::DM_M68K10) || (disasmMode == XBinary::DM_M68K20) || (disasmMode == XBinary::DM_M68K30) || (disasmMode == XBinary::DM_M68K40) ||
        (disasmMode == XBinary::DM_M68K60) || (disasmMode == XBinary::DM_TMS320C64X) || (disasmMode == XBinary::DM_M6800) || (disasmMode == XBinary::DM_M6801) ||
        (disasmMode == XBinary::DM_M6805) || (disasmMode == XBinary::DM_M6808) || (disasmMode == XBinary::DM_M6809) || (disasmMode == XBinary::DM_M6811) ||
        (disasmMode == XBinary::DM_CPU12) || (disasmMode == XBinary::DM_HD6301) || (disasmMode == XBinary::DM_HD6309) || (disasmMode == XBinary::DM_HCS08) ||
        (disasmMode == XBinary::DM_EVM) || (disasmMode == XBinary::DM_WASM) || (disasmMode == XBinary::DM_RISKV32) || (disasmMode == XBinary::DM_RISKV64) ||
        (disasmMode == XBinary::DM_RISKVC) || (disasmMode == XBinary::DM_MOS65XX) || (disasmMode == XBinary::DM_BPF_LE) || (disasmMode == XBinary::DM_BPF_BE)) {
        bResult = true;
    }

    return bResult;
}

cs_err XCapstone::openHandle(XBinary::DM disasmMode, csh *pHandle, bool bDetails, XBinary::SYNTAX syntax)
{
    //    printEnabledArchs();
    cs_err result = CS_ERR_HANDLE;

    // https://github.com/capstone-engine/capstone/blob/9907b22d33693f3beb4b8b7ba261fbdd219afee3/cstool/cstool.c
    if (disasmMode == XBinary::DM_X86_16) result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_16), pHandle);
    else if (disasmMode == XBinary::DM_X86_32) result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_32), pHandle);
    else if (disasmMode == XBinary::DM_X86_64) result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_64), pHandle);
    else if (disasmMode == XBinary::DM_ARM_LE) result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_ARM_BE) result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_AARCH64_LE) result = cs_open(CS_ARCH_ARM64, cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_AARCH64_BE) result = cs_open(CS_ARCH_ARM64, cs_mode(CS_MODE_ARM | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_CORTEXM) result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS), pHandle);
    else if (disasmMode == XBinary::DM_THUMB_LE) result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_THUMB_BE) result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS_LE) result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS_BE) result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS64_LE) result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS64_BE) result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC_LE) result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC_BE) result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_32 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC64_LE) result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC64_BE) result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_64 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_SPARC) result = cs_open(CS_ARCH_SPARC, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_SPARCV9) result = cs_open(CS_ARCH_SPARC, cs_mode(CS_MODE_BIG_ENDIAN | CS_MODE_V9), pHandle);
    else if (disasmMode == XBinary::DM_S390X) result = cs_open(CS_ARCH_SYSZ, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_XCORE) result = cs_open(CS_ARCH_XCORE, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M68K) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M68K00) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_000), pHandle);
    else if (disasmMode == XBinary::DM_M68K10) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_010), pHandle);
    else if (disasmMode == XBinary::DM_M68K20) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_020), pHandle);
    else if (disasmMode == XBinary::DM_M68K30) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_030), pHandle);
    else if (disasmMode == XBinary::DM_M68K40) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_040), pHandle);
    else if (disasmMode == XBinary::DM_M68K60) result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_060), pHandle);
    else if (disasmMode == XBinary::DM_TMS320C64X) result = cs_open(CS_ARCH_TMS320C64X, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M6800) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6800), pHandle);
    else if (disasmMode == XBinary::DM_M6801) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6801), pHandle);
    else if (disasmMode == XBinary::DM_M6805) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6805), pHandle);
    else if (disasmMode == XBinary::DM_M6808) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6808), pHandle);
    else if (disasmMode == XBinary::DM_M6809) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6809), pHandle);
    else if (disasmMode == XBinary::DM_M6811) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6811), pHandle);
    else if (disasmMode == XBinary::DM_CPU12) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_CPU12), pHandle);
    else if (disasmMode == XBinary::DM_HD6301) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6301), pHandle);
    else if (disasmMode == XBinary::DM_HD6309) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6309), pHandle);
    else if (disasmMode == XBinary::DM_HCS08) result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_HCS08), pHandle);
    else if (disasmMode == XBinary::DM_EVM) result = cs_open(CS_ARCH_EVM, cs_mode(0), pHandle);
    else if (disasmMode == XBinary::DM_WASM) result = cs_open(CS_ARCH_WASM, cs_mode(0), pHandle);
    else if (disasmMode == XBinary::DM_RISKV32) result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32), pHandle);
    else if (disasmMode == XBinary::DM_RISKV64) result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64), pHandle);
    else if (disasmMode == XBinary::DM_RISKVC) result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCVC), pHandle);
    else if (disasmMode == XBinary::DM_MOS65XX) result = cs_open(CS_ARCH_MOS65XX, cs_mode(0), pHandle);
    else if (disasmMode == XBinary::DM_BPF_LE) result = cs_open(CS_ARCH_BPF, cs_mode(CS_MODE_BPF_CLASSIC | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_BPF_BE) result = cs_open(CS_ARCH_BPF, cs_mode(CS_MODE_BPF_CLASSIC | CS_MODE_BIG_ENDIAN), pHandle);
    // TODO Check more

    if (result == CS_ERR_OK) {
        if (bDetails) {
            cs_option(*pHandle, CS_OPT_DETAIL, CS_OPT_ON);
        }

        if (syntax != XBinary::SYNTAX_DEFAULT) {
            if (syntax == XBinary::SYNTAX_ATT) {
                cs_option(*pHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
            } else if (syntax == XBinary::SYNTAX_INTEL) {
                cs_option(*pHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
            }
            if (syntax == XBinary::SYNTAX_MASM) {
                cs_option(*pHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM);
            }
            if (syntax == XBinary::SYNTAX_MOTOROLA) {
                cs_option(*pHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_MOTOROLA);
            }
            // TODO Check more
        }
    } else {
        *pHandle = 0;
    }

    return result;
}

cs_err XCapstone::closeHandle(csh *pHandle)
{
    cs_err result = CS_ERR_HANDLE;

    if (*pHandle) {
        result = cs_close(pHandle);
    }

    *pHandle = 0;

    return result;
}

void XCapstone::printEnabledArchs()
{
#ifdef QT_DEBUG
    // TODO Check more !!!
    if (cs_support(CS_ARCH_ARM)) qDebug() << "CS_ARCH_ARM";
    if (cs_support(CS_ARCH_ARM64)) qDebug() << "CS_ARCH_ARM64";
    if (cs_support(CS_ARCH_MIPS)) qDebug() << "CS_ARCH_MIPS";
    if (cs_support(CS_ARCH_X86)) qDebug() << "CS_ARCH_X86";
    if (cs_support(CS_ARCH_PPC)) qDebug() << "CS_ARCH_PPC";
    if (cs_support(CS_ARCH_SPARC)) qDebug() << "CS_ARCH_SPARC";
    if (cs_support(CS_ARCH_SYSZ)) qDebug() << "CS_ARCH_SYSZ";
    if (cs_support(CS_ARCH_XCORE)) qDebug() << "CS_ARCH_XCORE";
    if (cs_support(CS_ARCH_M68K)) qDebug() << "CS_ARCH_M68K";
    if (cs_support(CS_ARCH_TMS320C64X)) qDebug() << "CS_ARCH_TMS320C64X";
    if (cs_support(CS_ARCH_M680X)) qDebug() << "CS_ARCH_M680X";
    if (cs_support(CS_ARCH_EVM)) qDebug() << "CS_ARCH_EVM";
    if (cs_support(CS_ARCH_MOS65XX)) qDebug() << "CS_ARCH_MOS65XX";
    if (cs_support(CS_ARCH_WASM)) qDebug() << "CS_ARCH_WASM";
    if (cs_support(CS_ARCH_BPF)) qDebug() << "CS_ARCH_BPF";
    if (cs_support(CS_ARCH_RISCV)) qDebug() << "CS_ARCH_RISCV";

    // Additional build flags
    if (cs_support(CS_SUPPORT_DIET)) qDebug() << "CS_SUPPORT_DIET";
    if (cs_support(CS_SUPPORT_X86_REDUCE)) qDebug() << "CS_SUPPORT_X86_REDUCE";
#endif
}
