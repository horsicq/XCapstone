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

    if ((disasmMode == XBinary::DM_X86_16) || (disasmMode == XBinary::DM_X86_32) || (disasmMode == XBinary::DM_X86_64) ||
        (disasmMode == XBinary::DM_ARM_LE) || (disasmMode == XBinary::DM_ARM_BE) || (disasmMode == XBinary::DM_AARCH64_LE) ||
        (disasmMode == XBinary::DM_AARCH64_BE) || (disasmMode == XBinary::DM_CORTEXM) || (disasmMode == XBinary::DM_THUMB_LE) ||
        (disasmMode == XBinary::DM_THUMB_BE) || (disasmMode == XBinary::DM_MIPS_LE) || (disasmMode == XBinary::DM_MIPS_BE) ||
        (disasmMode == XBinary::DM_MIPS64_LE) || (disasmMode == XBinary::DM_MIPS64_BE) || (disasmMode == XBinary::DM_PPC_LE) ||
        (disasmMode == XBinary::DM_PPC_BE) || (disasmMode == XBinary::DM_PPC64_LE) || (disasmMode == XBinary::DM_PPC64_BE) ||
        (disasmMode == XBinary::DM_SPARC) || (disasmMode == XBinary::DM_SPARCV9) || (disasmMode == XBinary::DM_S390X) ||
        (disasmMode == XBinary::DM_XCORE) || (disasmMode == XBinary::DM_M68K) || (disasmMode == XBinary::DM_M68K00) ||
        (disasmMode == XBinary::DM_M68K10) || (disasmMode == XBinary::DM_M68K20) || (disasmMode == XBinary::DM_M68K30) ||
        (disasmMode == XBinary::DM_M68K40) || (disasmMode == XBinary::DM_M68K60) || (disasmMode == XBinary::DM_TMS320C64X) ||
        (disasmMode == XBinary::DM_M6800) || (disasmMode == XBinary::DM_M6801) || (disasmMode == XBinary::DM_M6805) ||
        (disasmMode == XBinary::DM_M6808) || (disasmMode == XBinary::DM_M6809) || (disasmMode == XBinary::DM_M6811) ||
        (disasmMode == XBinary::DM_CPU12) || (disasmMode == XBinary::DM_HD6301) || (disasmMode == XBinary::DM_HD6309) ||
        (disasmMode == XBinary::DM_HCS08) || (disasmMode == XBinary::DM_EVM) || (disasmMode == XBinary::DM_WASM) ||
        (disasmMode == XBinary::DM_RISKV32) || (disasmMode == XBinary::DM_RISKV64) || (disasmMode == XBinary::DM_RISKVC) ||
        (disasmMode == XBinary::DM_MOS65XX) || (disasmMode == XBinary::DM_BPF_LE) || (disasmMode == XBinary::DM_BPF_BE)) {
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
    else if (disasmMode == XBinary::DM_MOS65XX) result = cs_open(CS_ARCH_M680X, cs_mode(CS_ARCH_MOS65XX), pHandle);
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

bool XCapstone::isBranchOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    return isJumpOpcode(dmFamily, nOpcodeID) || isCondJumpOpcode(dmFamily, nOpcodeID) || isCallOpcode(dmFamily, nOpcodeID);
}

bool XCapstone::isJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        if (nOpcodeID == ARM_INS_B) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (nOpcodeID == ARM64_INS_B) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (nOpcodeID == BPF_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((nOpcodeID == MIPS_INS_J) || (nOpcodeID == MIPS_INS_JAL)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_JMP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (nOpcodeID == M68K_INS_BRA) {
            bResult = true;
        }
    }

    // TODO Other archs

    return bResult;
}

bool XCapstone::isJumpOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        if (sOpcode == "b") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (sOpcode == "b") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (sOpcode == "jmp") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if ((sOpcode == "j") || (sOpcode == "jal")) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (sOpcode == "bra") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isRetOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_RET) || (nOpcodeID == X86_INS_RETF) || (nOpcodeID == X86_INS_RETFQ)) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (nOpcodeID == ARM64_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_BPF) {
        if (nOpcodeID == BPF_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_RET) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if (nOpcodeID == MIPS_INS_JR) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((nOpcodeID == M68K_INS_RTS) || (nOpcodeID == M68K_INS_RTE) || (nOpcodeID == M68K_INS_RTR) || (nOpcodeID == M68K_INS_RTD)) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isRetOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "retw") || (sOpcode == "retl") || (sOpcode == "retq")) {
                bResult = true;
            }
        } else {
            if ((sOpcode == "ret") || (sOpcode == "retf")) {
                bResult = true;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        if (sOpcode == "ret") {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if ((sOpcode == "rte") || (sOpcode == "rts") || (sOpcode == "rtr") || (sOpcode == "rtd")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isCallOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_CALL) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isCallOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "callw") || (sOpcode == "calll") || (sOpcode == "callq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "call") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isCondJumpOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((nOpcodeID == X86_INS_JA) || (nOpcodeID == X86_INS_JAE) || (nOpcodeID == X86_INS_JB) || (nOpcodeID == X86_INS_JBE) || (nOpcodeID == X86_INS_JCXZ) ||
            (nOpcodeID == X86_INS_JE) || (nOpcodeID == X86_INS_JECXZ) || (nOpcodeID == X86_INS_JG) || (nOpcodeID == X86_INS_JGE) || (nOpcodeID == X86_INS_JL) ||
            (nOpcodeID == X86_INS_JLE) || (nOpcodeID == X86_INS_JNE) || (nOpcodeID == X86_INS_JNO) || (nOpcodeID == X86_INS_JNP) || (nOpcodeID == X86_INS_JNS) ||
            (nOpcodeID == X86_INS_JO) || (nOpcodeID == X86_INS_JP) || (nOpcodeID == X86_INS_JRCXZ) || (nOpcodeID == X86_INS_JS) || (nOpcodeID == X86_INS_LOOP) ||
            (nOpcodeID == X86_INS_LOOPE) || (nOpcodeID == X86_INS_LOOPNE)) {
            bResult = true;
        }
    }

    return bResult;
}

bool XCapstone::isCondJumpOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sOpcode == "je") || (sOpcode == "jne") || (sOpcode == "jz") || (sOpcode == "jnz") || (sOpcode == "ja") || (sOpcode == "jc") || (sOpcode == "jb") ||
            (sOpcode == "jo") || (sOpcode == "jno") || (sOpcode == "js") || (sOpcode == "jns") || (sOpcode == "jae") || (sOpcode == "jbe") || (sOpcode == "jl") ||
            (sOpcode == "jge") || (sOpcode == "jg") || (sOpcode == "jb") || (sOpcode == "loop") || (sOpcode == "loopne") || (sOpcode == "loope")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isNopOpcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_M68K) {
        if (nOpcodeID == M68K_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MOS65XX) {
        if (nOpcodeID == MOS65XX_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_MIPS) {
        if (nOpcodeID == MIPS_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_SPARC) {
        if (nOpcodeID == SPARC_INS_NOP) {
            bResult = true;
        }
    } else if (dmFamily == XBinary::DMFAMILY_WASM) {
        if (nOpcodeID == WASM_INS_NOP) {
            bResult = true;
        }
    }

    return bResult;
}

bool XCapstone::isNopOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "nopw") || (sOpcode == "nopl") || (sOpcode == "nopq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "nop") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isInt3Opcode(XBinary::DMFAMILY dmFamily, quint32 nOpcodeID)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (nOpcodeID == X86_INS_INT3) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isInt3Opcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "int3") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isSyscallOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (sOpcode == "syscall") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isPushOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "pushw") || (sOpcode == "pushl") || (sOpcode == "pushq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "push") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isPopOpcode(XBinary::DMFAMILY dmFamily, const QString &sOpcode, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            if ((sOpcode == "popw") || (sOpcode == "popl") || (sOpcode == "popq")) {
                bResult = true;
            }
        } else {
            if (sOpcode == "pop") {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isGeneralRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = sRegister;

        if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sRegister.size();

            if (nSize >= 2) {
                if (_sRegister.at(0) == QChar('%')) {
                    bResult = true;
                    _sRegister = _sRegister.right(_sRegister.size() - 1);
                }
            }
        } else {
            bResult = true;
        }

        if (bResult) {
            if ((_sRegister == "al") || (_sRegister == "ah") || (_sRegister == "bl") || (_sRegister == "bh") || (_sRegister == "cl") || (_sRegister == "ch") ||
                (_sRegister == "dl") || (_sRegister == "dh") || (_sRegister == "ax") || (_sRegister == "bx") || (_sRegister == "cx") || (_sRegister == "dx") ||
                (_sRegister == "si") || (_sRegister == "di") || (_sRegister == "sp") || (_sRegister == "bp") || (_sRegister == "eax") || (_sRegister == "ebx") ||
                (_sRegister == "ecx") || (_sRegister == "edx") || (_sRegister == "esi") || (_sRegister == "edi") || (_sRegister == "esp") || (_sRegister == "ebp") ||
                (_sRegister == "rax") || (_sRegister == "rbx") || (_sRegister == "rcx") || (_sRegister == "rdx") || (_sRegister == "rsi") || (_sRegister == "rdi") ||
                (_sRegister == "rsp") || (_sRegister == "rbp") || (_sRegister == "r8") || (_sRegister == "r9") || (_sRegister == "r10") || (_sRegister == "r11") ||
                (_sRegister == "r12") || (_sRegister == "r13") || (_sRegister == "r14") || (_sRegister == "r15") || (_sRegister == "r8b") || (_sRegister == "r9b") ||
                (_sRegister == "r10b") || (_sRegister == "r11b") || (_sRegister == "r12b") || (_sRegister == "r13b") || (_sRegister == "r14b") ||
                (_sRegister == "r15b") || (_sRegister == "r8d") || (_sRegister == "r9d") || (_sRegister == "r10d") || (_sRegister == "r11d") || (_sRegister == "r12d") ||
                (_sRegister == "r13d") || (_sRegister == "r14d") || (_sRegister == "r15d")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM) {
        qint32 nSize = sRegister.size();

        if (nSize >= 2) {
            if (sRegister.at(0) == QChar('r')) {
                bResult = true;
            }
        }
    } else if (dmFamily == XBinary::DMFAMILY_ARM64) {
        qint32 nSize = sRegister.size();

        if (nSize >= 2) {
            if (sRegister.at(0) == QChar('x')) {
                bResult = true;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isStackRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = removeRegPrefix(dmFamily, sRegister, syntax);

        if (_sRegister != "") {
            if ((_sRegister == "sp") || (_sRegister == "bp") || (_sRegister == "esp") || (_sRegister == "ebp") || (_sRegister == "rsp") || (_sRegister == "rbp")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        if (sRegister == "sp") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isSegmentRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        QString _sRegister = removeRegPrefix(dmFamily, sRegister, syntax);

        if (_sRegister != "") {
            if ((sRegister == "es") || (sRegister == "gs") || (sRegister == "ss") || (sRegister == "ds") || (sRegister == "cs") || (sRegister == "fs")) {
                bResult = true;
            } else {
                bResult = false;
            }
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isDebugRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "dr0") || (sRegister == "dr1") || (sRegister == "dr2") || (sRegister == "dr3") || (sRegister == "dr6") || (sRegister == "dr7")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isInstructionPointerRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "ip") || (sRegister == "eip") || (sRegister == "rip")) {
            bResult = true;
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        if (sRegister == "pc") {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isFlagsRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((sRegister == "flags") || (sRegister == "eflags") || (sRegister == "rflags")) {
            bResult = true;
        }
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isFPURegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)
    Q_UNUSED(sRegister)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        // TODO
    }
    // TODO Other archs

    return bResult;
}

bool XCapstone::isXMMRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    Q_UNUSED(syntax)

    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        qint32 nSize = sRegister.size();

        if (syntax == XBinary::SYNTAX_ATT) {
            if (nSize >= 5) {
                if (sRegister.left(4) == "%xmm") {
                    bResult = true;
                }
            }
        } else {
            if (nSize >= 4) {
                if (sRegister.left(3) == "xmm") {
                    bResult = true;
                }
            }
        }
    }

    return bResult;
}

bool XCapstone::isRegister(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    return (isGeneralRegister(dmFamily, sRegister, syntax) || isSegmentRegister(dmFamily, sRegister, syntax) || isDebugRegister(dmFamily, sRegister, syntax) ||
            isInstructionPointerRegister(dmFamily, sRegister, syntax) || isFlagsRegister(dmFamily, sRegister, syntax) || isFPURegister(dmFamily, sRegister, syntax) ||
            isXMMRegister(dmFamily, sRegister, syntax));
}

bool XCapstone::isRef(XBinary::DMFAMILY dmFamily, const QString &sOperand, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    Q_UNUSED(dmFamily)
    Q_UNUSED(syntax)

    if (sOperand.contains("<")) {
        bResult = true;
    }

    return bResult;
}

bool XCapstone::isNumber(XBinary::DMFAMILY dmFamily, const QString &sNumber, XBinary::SYNTAX syntax)
{
    bool bResult = false;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if ((syntax == XBinary::SYNTAX_DEFAULT) || (syntax == XBinary::SYNTAX_INTEL)) {
            qint32 nSize = sNumber.size();
            if (nSize == 1) {
                bResult = true;
            } else if (nSize >= 2) {
                if (sNumber.left(2) == "0x") {
                    bResult = true;
                } else if (sNumber.at(0) == QChar('-')) {
                    bResult = true;
                }
            }
        } else if (syntax == XBinary::SYNTAX_MASM) {
            qint32 nSize = sNumber.size();
            if (nSize == 1) {
                bResult = true;
            } else if (nSize > 1) {
                if (sNumber.right(1) == "h") {
                    bResult = true;
                }
            }
        } else if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sNumber.size();
            if ((nSize >= 2) && (sNumber.at(0) == QChar('$')) && (!sNumber.contains(", "))) {
                bResult = true;
            }
        }
    } else if ((dmFamily == XBinary::DMFAMILY_ARM) || (dmFamily == XBinary::DMFAMILY_ARM64)) {
        // TODO
    }
    // TODO Other archs

    return bResult;
}

QString XCapstone::removeRegPrefix(XBinary::DMFAMILY dmFamily, const QString &sRegister, XBinary::SYNTAX syntax)
{
    QString sResult = sRegister;

    if (dmFamily == XBinary::DMFAMILY_X86) {
        if (syntax == XBinary::SYNTAX_ATT) {
            qint32 nSize = sRegister.size();

            sResult = "";

            if (nSize >= 2) {
                if (sRegister.at(0) == QChar('%')) {
                    sResult = sRegister.right(sRegister.size() - 1);
                }
            }
        }
    }

    return sResult;
}

void XCapstone::_addOperandPart(QList<OPERANDPART> *pListOperandParts, const QString &sString, bool bIsMain)
{
    if (sString != "") {
        OPERANDPART record = {};
        record.sString = sString;
        record.bIsMain = bIsMain;

        pListOperandParts->append(record);
    }
}

QList<XCapstone::OPERANDPART> XCapstone::getOperandParts(XBinary::DMFAMILY dmFamily, const QString &sString, XBinary::SYNTAX syntax)
{
    Q_UNUSED(dmFamily)
    Q_UNUSED(syntax)

    QList<XCapstone::OPERANDPART> listResult;

    qint32 nNumberOfSymbols = sString.size();

    QString sBuffer;

    for (qint32 i = 0; i < nNumberOfSymbols; i++) {
        QChar cChar = sString.at(i);

        bool bNewPart = false;

        if ((cChar == QChar(' ')) || (cChar == QChar(',')) || (cChar == QChar(':')) || (cChar == QChar('[')) || (cChar == QChar(']')) || (cChar == QChar('{')) ||
            (cChar == QChar('}')) || (cChar == QChar('(')) || (cChar == QChar(')')) || (cChar == QChar('!'))) {
            bNewPart = true;
        }

        if (bNewPart) {
            _addOperandPart(&listResult, sBuffer, true);
            _addOperandPart(&listResult, cChar, false);
            sBuffer = "";
        } else {
            sBuffer += cChar;
        }
    }

    _addOperandPart(&listResult, sBuffer, true);

    return listResult;
}

void XCapstone::printEnabledArchs()
{
#ifdef QT_DEBUG
    // TODO Check more !!!
    if (cs_support(CS_ARCH_ARM)) qDebug("CS_ARCH_ARM");
    if (cs_support(CS_ARCH_ARM64)) qDebug("CS_ARCH_ARM64");
    if (cs_support(CS_ARCH_MIPS)) qDebug("CS_ARCH_MIPS");
    if (cs_support(CS_ARCH_X86)) qDebug("CS_ARCH_X86");
    if (cs_support(CS_ARCH_PPC)) qDebug("CS_ARCH_PPC");
    if (cs_support(CS_ARCH_SPARC)) qDebug("CS_ARCH_SPARC");
    if (cs_support(CS_ARCH_SYSZ)) qDebug("CS_ARCH_SYSZ");
    if (cs_support(CS_ARCH_XCORE)) qDebug("CS_ARCH_XCORE");
    if (cs_support(CS_ARCH_M68K)) qDebug("CS_ARCH_M68K");
    if (cs_support(CS_ARCH_TMS320C64X)) qDebug("CS_ARCH_TMS320C64X");
    if (cs_support(CS_ARCH_M680X)) qDebug("CS_ARCH_M680X");
    if (cs_support(CS_ARCH_EVM)) qDebug("CS_ARCH_EVM");
    if (cs_support(CS_ARCH_MOS65XX)) qDebug("CS_ARCH_MOS65XX");
    if (cs_support(CS_ARCH_WASM)) qDebug("CS_ARCH_WASM");
    if (cs_support(CS_ARCH_BPF)) qDebug("CS_ARCH_BPF");
    if (cs_support(CS_ARCH_RISCV)) qDebug("CS_ARCH_RISCV");
#endif
}
