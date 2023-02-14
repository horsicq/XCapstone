/* Copyright (c) 2019-2023 hors<horsicq@gmail.com>
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

XCapstone::XCapstone(QObject *pParent) : QObject(pParent) {
}

cs_err XCapstone::openHandle(XBinary::DM disasmMode, csh *pHandle, bool bDetails, XBinary::SYNTAX syntax) {
    //    printEnabledArchs();
    cs_err result = CS_ERR_HANDLE;

    if (disasmMode == XBinary::DM_X86_16)
        result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_16), pHandle);
    else if (disasmMode == XBinary::DM_X86_32)
        result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_32), pHandle);
    else if (disasmMode == XBinary::DM_X86_64)
        result = cs_open(CS_ARCH_X86, cs_mode(CS_MODE_64), pHandle);
    else if (disasmMode == XBinary::DM_ARM_LE)
        result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_ARM_BE)
        result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_ARM64_LE)
        result = cs_open(CS_ARCH_ARM64, cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_ARM64_BE)
        result = cs_open(CS_ARCH_ARM64, cs_mode(CS_MODE_ARM | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_CORTEXM)
        result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS), pHandle);
    else if (disasmMode == XBinary::DM_THUMB_LE)
        result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_THUMB_BE)
        result = cs_open(CS_ARCH_ARM, cs_mode(CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS_LE)
        result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS_BE)
        result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS64_LE)
        result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_MIPS64_BE)
        result = cs_open(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC_LE)
        result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_32 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC_BE)
        result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_32 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC64_LE)
        result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_64 | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_PPC64_BE)
        result = cs_open(CS_ARCH_PPC, cs_mode(CS_MODE_64 | CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_SPARC)
        result = cs_open(CS_ARCH_SPARC, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_S390X)
        result = cs_open(CS_ARCH_SYSZ, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_XCORE)
        result = cs_open(CS_ARCH_XCORE, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M68K)
        result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M68K40)
        result = cs_open(CS_ARCH_M68K, cs_mode(CS_MODE_M68K_040), pHandle);
    else if (disasmMode == XBinary::DM_TMS320C64X)
        result = cs_open(CS_ARCH_TMS320C64X, cs_mode(CS_MODE_BIG_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_M6800)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6800), pHandle);
    else if (disasmMode == XBinary::DM_M6801)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6801), pHandle);
    else if (disasmMode == XBinary::DM_M6805)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6805), pHandle);
    else if (disasmMode == XBinary::DM_M6808)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6808), pHandle);
    else if (disasmMode == XBinary::DM_M6809)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6809), pHandle);
    else if (disasmMode == XBinary::DM_M6811)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6811), pHandle);
    else if (disasmMode == XBinary::DM_CPU12)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_CPU12), pHandle);
    else if (disasmMode == XBinary::DM_HD6301)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6301), pHandle);
    else if (disasmMode == XBinary::DM_HD6309)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_6309), pHandle);
    else if (disasmMode == XBinary::DM_HCS08)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_MODE_M680X_HCS08), pHandle);
    else if (disasmMode == XBinary::DM_EVM)
        result = cs_open(CS_ARCH_EVM, cs_mode(0), pHandle);
    else if (disasmMode == XBinary::DM_WASM)
        result = cs_open(CS_ARCH_WASM, cs_mode(0), pHandle);
    else if (disasmMode == XBinary::DM_RISKV32)
        result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV32), pHandle);
    else if (disasmMode == XBinary::DM_RISKV64)
        result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCV64), pHandle);
    else if (disasmMode == XBinary::DM_RISKVC)
        result = cs_open(CS_ARCH_RISCV, cs_mode(CS_MODE_RISCVC), pHandle);
    else if (disasmMode == XBinary::DM_MOS65XX)
        result = cs_open(CS_ARCH_M680X, cs_mode(CS_ARCH_MOS65XX), pHandle);
    else if (disasmMode == XBinary::DM_BPF_LE)
        result = cs_open(CS_ARCH_BPF, cs_mode(CS_MODE_BPF_CLASSIC | CS_MODE_LITTLE_ENDIAN), pHandle);
    else if (disasmMode == XBinary::DM_BPF_BE)
        result = cs_open(CS_ARCH_BPF, cs_mode(CS_MODE_BPF_CLASSIC | CS_MODE_BIG_ENDIAN), pHandle);
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

cs_err XCapstone::closeHandle(csh *pHandle) {
    cs_err result = CS_ERR_HANDLE;

    if (*pHandle) {
        result = cs_close(pHandle);
        *pHandle = 0;
    }

    return result;
}

XCapstone::DISASM_STRUCT XCapstone::disasm(csh handle, XADDR nAddress, char *pData, qint32 nDataSize) {
    DISASM_STRUCT result = {};

    cs_insn *pInsn = nullptr;

    size_t nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

    if (nNumberOfOpcodes > 0) {
        result.nAddress = nAddress;
        result.nSize = pInsn->size;
        result.nOpcodeID = pInsn->id;

        QString sMnemonic = pInsn->mnemonic;
        QString sStr = pInsn->op_str;

        result.sString += sMnemonic;

        if (sStr != "") result.sString += QString(" %1").arg(sStr);

        cs_free(pInsn, nNumberOfOpcodes);
    }

    return result;
}

XCapstone::DISASM_STRUCT XCapstone::disasm(csh handle, QIODevice *pDevice, qint64 nOffset, XADDR nAddress) {
    QByteArray baData = XBinary::read_array(pDevice, nOffset, N_OPCODE_SIZE);

    return disasm(handle, nAddress, baData.data(), baData.size());
}

XCapstone::DISASM_RESULT XCapstone::disasm_ex(csh handle, XBinary::DM disasmMode, char *pData, qint32 nDataSize, XADDR nAddress, DISASM_OPTIONS disasmOptions)
{
    DISASM_RESULT result = {};

    result.nAddress = nAddress;

    if (handle) {
        cs_insn *pInsn = nullptr;

        quint64 nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

        if (nNumberOfOpcodes > 0) {
            result.sMnemonic = pInsn->mnemonic;
            result.sString = pInsn->op_str;

            result.nSize = pInsn->size;
            result.bIsValid = true;

            // Relatives
            for (qint32 i = 0; i < pInsn->detail->groups_count; i++) {
                if (pInsn->detail->groups[i] == CS_GRP_BRANCH_RELATIVE) {
                    if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
                        for (qint32 j = 0; j < pInsn->detail->x86.op_count; j++) {
                            if (pInsn->detail->x86.operands[j].type == X86_OP_IMM) {
                                switch (pInsn->id) {
                                    case X86_INS_LOOP:
                                    case X86_INS_LOOPE:
                                    case X86_INS_LOOPNE:
                                    case X86_INS_JAE:
                                    case X86_INS_JA:
                                    case X86_INS_JBE:
                                    case X86_INS_JB:
                                    case X86_INS_JCXZ:
                                    case X86_INS_JECXZ:
                                    case X86_INS_JE:
                                    case X86_INS_JGE:
                                    case X86_INS_JG:
                                    case X86_INS_JLE:
                                    case X86_INS_JL:
                                    case X86_INS_JNE:
                                    case X86_INS_JNO:
                                    case X86_INS_JNP:
                                    case X86_INS_JNS:
                                    case X86_INS_JO:
                                    case X86_INS_JP:
                                    case X86_INS_JRCXZ:
                                    case X86_INS_JS:
                                        result.relType = RELTYPE_JMP_COND;
                                        break;
                                    case X86_INS_CALL:
                                        result.relType = RELTYPE_CALL;
                                        break;
                                    case X86_INS_JMP:
                                        result.relType = RELTYPE_JMP_UNCOND;
                                        break;
                                    default:
                                        result.relType = RELTYPE_JMP; // TODO
                                }

                                result.nXrefToRelative = pInsn->detail->x86.operands[j].imm;

                                break;
                            }
                        }
                    } else if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM) {
                        for (qint32 j = 0; j < pInsn->detail->arm.op_count; j++) {
                            if (pInsn->detail->arm.operands[j].type == ARM_OP_IMM) {
                                result.relType = RELTYPE_JMP; // TODO
                                result.nXrefToRelative = pInsn->detail->arm.operands[j].imm;

                                break;
                            }
                        }
                    } else if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_ARM64) {
                        for (qint32 j = 0; j < pInsn->detail->arm64.op_count; j++) {
                            if (pInsn->detail->arm64.operands[j].type == ARM64_OP_IMM) {
                                result.relType = RELTYPE_JMP; // TODO
                                result.nXrefToRelative = pInsn->detail->arm64.operands[j].imm;

                                break;
                            }
                        }
                    }

                    break;
                }
            }

            // Memory
            if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
                for (qint32 i = 0; i < pInsn->detail->x86.op_count; i++) {
                    if (pInsn->detail->x86.operands[i].type == X86_OP_MEM) {

                        bool bLEA = (pInsn->id == X86_INS_LEA);

                        if ((pInsn->detail->x86.operands[i].mem.base == X86_REG_INVALID) &&
                            (pInsn->detail->x86.operands[i].mem.index == X86_REG_INVALID)) {
                            result.memType = MEMTYPE_READ; // TODO
                            result.nXrefToMemory = pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            break;
                        } else if ((pInsn->detail->x86.operands[i].mem.base == X86_REG_RIP) &&
                                   (pInsn->detail->x86.operands[i].mem.index == X86_REG_INVALID)) {
                            result.memType = MEMTYPE_READ; // TODO
                            result.nXrefToMemory = nAddress + pInsn->size + pInsn->detail->x86.operands[i].mem.disp;
                            result.nMemorySize = pInsn->detail->x86.operands[i].size;

                            if (bLEA) {
                                result.nMemorySize = 0;
                            }

                            QString sOldString;
                            QString sNewString;

                            // TODO all syntaxes
                            if (result.sString.contains("rip + 0x")) { // Intel
                                sOldString = QString("rip + 0x%1").arg(pInsn->detail->x86.operands[i].mem.disp, 0, 16);
                                sNewString = QString("0x%1").arg(result.nXrefToMemory, 0, 16);
                            } /*else if ("(%rip)") {
                                sOldString = QString("rip + 0x%1").arg(pInsn->detail->x86.operands[i].mem.disp, 0, 16);
                                sNewString = QString("0x%1").arg(result.nXrefToMemory, 0, 16);
                            }*/

                            result.sString = result.sString.replace(sOldString, sNewString);

                            break;
                        }
                    }
                }
            }

//            if (disasmMode == XBinary::DM_X86_64) {
//                if (result.sString.contains("[rip + 0x")) {
//                    // TODO
//                    qint32 nNumberOfOpcodes = pInsn->detail->x86.op_count;

//                    for (qint32 i = 0; i < nNumberOfOpcodes; i++) {

//                    }
//                }
//            }

            cs_free(pInsn, nNumberOfOpcodes);
        } else {
            result.sMnemonic = tr("Invalid opcode");
            result.nSize = 1;
        }
    } else {
        result.nSize = 1;
    }

    return result;
}

qint32 XCapstone::getDisasmLength(csh handle, XADDR nAddress, char *pData, qint32 nDataSize) {
    qint32 nResult = 0;

    cs_insn *pInsn = nullptr;

    size_t nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

    if (nNumberOfOpcodes > 0) {
        nResult = pInsn->size;

        cs_free(pInsn, nNumberOfOpcodes);
    }

    return nResult;
}

qint32 XCapstone::getDisasmLength(csh handle, QIODevice *pDevice, qint64 nOffset, XADDR nAddress) {
    QByteArray baData = XBinary::read_array(pDevice, nOffset, N_OPCODE_SIZE);

    return getDisasmLength(handle, nAddress, baData.data(), baData.size());
}

qint64 XCapstone::getNextAddress(csh handle, XADDR nAddress, char *pData, qint32 nDataSize) {
    qint64 nResult = -1;

    cs_insn *pInsn = nullptr;

    size_t nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

    if (nNumberOfOpcodes > 0) {
        nResult = nAddress + pInsn->size;

        if (isJmpOpcode(pInsn->id) || isCallOpcode(pInsn->id)) {
            // TODO other archs !!! ARM/ARM64
            for (qint32 i = 0; i < pInsn->detail->x86.op_count; i++) {
                if (pInsn->detail->x86.operands[i].type == X86_OP_IMM) {
                    nResult = pInsn->detail->x86.operands[i].imm;
                }
            }
        }

        cs_free(pInsn, nNumberOfOpcodes);
    }

    return nResult;
}

qint64 XCapstone::getNextAddress(csh handle, QIODevice *pDevice, qint64 nOffset, XADDR nAddress) {
    QByteArray baData = XBinary::read_array(pDevice, nOffset, N_OPCODE_SIZE);

    return getNextAddress(handle, nAddress, baData.data(), baData.size());
}

XCapstone::OPCODE_ID XCapstone::getOpcodeID(csh handle, XADDR nAddress, char *pData, qint32 nDataSize) {
    OPCODE_ID result = {};

    cs_insn *pInsn = nullptr;

    size_t nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)pData, nDataSize, nAddress, 1, &pInsn);

    if (nNumberOfOpcodes > 0) {
        result.nSize = pInsn->size;
        result.nOpcodeID = pInsn->id;

        cs_free(pInsn, nNumberOfOpcodes);
    }

    return result;
}

bool XCapstone::isJmpOpcode(quint16 nOpcodeID) {
    // TODO another archs
    bool bResult = false;

    if ((nOpcodeID == X86_INS_JMP) || (nOpcodeID == X86_INS_JA) || (nOpcodeID == X86_INS_JAE) || (nOpcodeID == X86_INS_JB) || (nOpcodeID == X86_INS_JBE) ||
        (nOpcodeID == X86_INS_JCXZ) || (nOpcodeID == X86_INS_JE) || (nOpcodeID == X86_INS_JECXZ) || (nOpcodeID == X86_INS_JG) || (nOpcodeID == X86_INS_JGE) ||
        (nOpcodeID == X86_INS_JL) || (nOpcodeID == X86_INS_JLE) || (nOpcodeID == X86_INS_JNE) || (nOpcodeID == X86_INS_JNO) || (nOpcodeID == X86_INS_JNP) ||
        (nOpcodeID == X86_INS_JNS) || (nOpcodeID == X86_INS_JO) || (nOpcodeID == X86_INS_JP) || (nOpcodeID == X86_INS_JRCXZ) || (nOpcodeID == X86_INS_JS) ||
        (nOpcodeID == X86_INS_LOOP) || (nOpcodeID == X86_INS_LOOPE) || (nOpcodeID == X86_INS_LOOPNE)) {
        bResult = true;
    }

    return bResult;
}

bool XCapstone::isRetOpcode(quint16 nOpcodeID) {
    bool bResult = false;

    if ((nOpcodeID == X86_INS_RET) || (nOpcodeID == X86_INS_RETF) || (nOpcodeID == X86_INS_RETFQ)) {
        bResult = true;
    }

    return bResult;
}

bool XCapstone::isCallOpcode(quint16 nOpcodeID) {
    bool bResult = false;

    if (nOpcodeID == X86_INS_CALL) {
        bResult = true;
    }

    return bResult;
}

QString XCapstone::getSignature(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, XADDR nAddress, ST signatureType, qint32 nCount) {
    QString sResult;

    csh handle = 0;

    XBinary::DM disasmMode = XBinary::getDisasmMode(pMemoryMap);

    openHandle(disasmMode, &handle, true);

    if (handle) {
        while (nCount > 0) {
            qint64 nOffset = XBinary::addressToOffset(pMemoryMap, nAddress);

            if (nOffset == -1) {
                break;
            }

            QByteArray baData = XBinary::read_array(pDevice, nOffset, 15);

            cs_insn *pInsn = 0;

            size_t nNumberOfOpcodes = cs_disasm(handle, (uint8_t *)baData.data(), baData.size(), nAddress, 1, &pInsn);

            if (nNumberOfOpcodes > 0) {
                quint32 nDispOffset = 0;
                quint32 nDispSize = 0;
                quint32 nImmOffset = 0;
                quint32 nImmSize = 0;

                if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
                    nDispOffset = pInsn->detail->x86.encoding.disp_offset;
                    nDispSize = pInsn->detail->x86.encoding.disp_size;
                    nImmOffset = pInsn->detail->x86.encoding.imm_offset;
                    nImmSize = pInsn->detail->x86.encoding.imm_size;
                } else if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
                    // TODO
                }

                baData.resize(pInsn->size);

                QString sHEX = baData.toHex().data();

                if ((signatureType == ST_FULL) || (signatureType == ST_MASK)) {
                    nAddress += pInsn->size;

                    if (signatureType == ST_MASK) {
                        if (nDispSize) {
                            sHEX = replaceWildChar(sHEX, nDispOffset, nDispSize, '.');
                        }

                        if (nImmSize) {
                            sHEX = replaceWildChar(sHEX, nImmOffset, nImmSize, '.');
                        }
                    }
                } else if (signatureType == ST_MASKREL) {
                    bool bIsJump = false;

                    if (isJmpOpcode(pInsn->id) || isCallOpcode(pInsn->id)) {
                        // TODO another archs !!!
                        if (XBinary::getDisasmFamily(disasmMode) == XBinary::DMFAMILY_X86) {
                            for (qint32 i = 0; i < pInsn->detail->x86.op_count; i++) {
                                if (pInsn->detail->x86.operands[i].type == X86_OP_IMM)  // TODO another archs !!!
                                {
                                    nAddress = pInsn->detail->x86.operands[i].imm;

                                    if ((pMemoryMap->fileType == XBinary::FT_COM) && (pInsn->detail->x86.encoding.imm_size == 2)) {
                                        if (nAddress > 0xFFFF) {
                                            nAddress &= 0xFFFF;
                                        }
                                    }

                                    sHEX = replaceWildChar(sHEX, nImmOffset, nImmSize, '$');

                                    bIsJump = true;
                                }
                            }
                        } else {
                            nAddress += pInsn->size;
                        }
                    } else {
                        nAddress += pInsn->size;
                    }

                    if (!bIsJump) {
                        if (nDispSize) {
                            sHEX = replaceWildChar(sHEX, nDispOffset, nDispSize, '.');
                        }

                        if (nImmSize) {
                            sHEX = replaceWildChar(sHEX, nImmOffset, nImmSize, '.');
                        }
                    }
                }

                sResult += sHEX;

                cs_free(pInsn, nNumberOfOpcodes);
            } else {
                break;
            }

            nCount--;
        }

        closeHandle(&handle);
    }

    return sResult;
}

QString XCapstone::replaceWildChar(QString sString, qint32 nOffset, qint32 nSize, QChar cWild) {
    QString sResult = sString;
    QString sWild;

    sWild = sWild.fill(cWild, nSize * 2);

    sResult = sResult.replace(nOffset * 2, nSize * 2, sWild);

    return sResult;
}

void XCapstone::printEnabledArchs() {
#ifdef QT_DEBUG
    // TODO Check more
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
