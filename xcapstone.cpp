// copyright (c) 2019-2021 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include "xcapstone.h"

#if defined(_MSC_VER)
#if _MSC_VER > 1800
#pragma comment(lib, "legacy_stdio_definitions.lib") // vsprintf // TODO Check
#endif
#endif

XCapstone::XCapstone(QObject *pParent) : QObject(pParent)
{

}

cs_err XCapstone::openHandle(XBinary::DM disasmMode, csh *pHandle, bool bDetails)
{
    cs_err result=CS_ERR_HANDLE;

    if      (disasmMode==XBinary::DM_X86_16)        result=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_16),pHandle);
    else if (disasmMode==XBinary::DM_X86_32)        result=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_32),pHandle);
    else if (disasmMode==XBinary::DM_X86_64)        result=cs_open(CS_ARCH_X86,cs_mode(CS_MODE_64),pHandle);
    else if (disasmMode==XBinary::DM_ARM_LE)        result=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_ARM_BE)        result=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_ARM64_LE)      result=cs_open(CS_ARCH_ARM64,cs_mode(CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_ARM64_BE)      result=cs_open(CS_ARCH_ARM64,cs_mode(CS_MODE_ARM|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_CORTEXM)       result=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_MCLASS),pHandle);
    else if (disasmMode==XBinary::DM_THUMB_LE)      result=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_THUMB_BE)      result=cs_open(CS_ARCH_ARM,cs_mode(CS_MODE_ARM|CS_MODE_THUMB|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_MIPS_LE)       result=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS32|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_MIPS_BE)       result=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS32|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_MIPS64_LE)     result=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS64|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_MIPS64_BE)     result=cs_open(CS_ARCH_MIPS,cs_mode(CS_MODE_MIPS64|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_PPC_LE)        result=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_32|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_PPC_BE)        result=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_32|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_PPC64_LE)      result=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_64|CS_MODE_LITTLE_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_PPC64_BE)      result=cs_open(CS_ARCH_PPC,cs_mode(CS_MODE_64|CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_SPARC)         result=cs_open(CS_ARCH_SPARC,cs_mode(CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_S390X)         result=cs_open(CS_ARCH_SYSZ,cs_mode(CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_XCORE)         result=cs_open(CS_ARCH_XCORE,cs_mode(CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_M68K)          result=cs_open(CS_ARCH_M68K,cs_mode(CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_M68K40)        result=cs_open(CS_ARCH_M68K,cs_mode(CS_MODE_M68K_040),pHandle);
    else if (disasmMode==XBinary::DM_TMS320C64X)    result=cs_open(CS_ARCH_TMS320C64X,cs_mode(CS_MODE_BIG_ENDIAN),pHandle);
    else if (disasmMode==XBinary::DM_M6800)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6800),pHandle);
    else if (disasmMode==XBinary::DM_M6801)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6801),pHandle);
    else if (disasmMode==XBinary::DM_M6805)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6805),pHandle);
    else if (disasmMode==XBinary::DM_M6808)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6808),pHandle);
    else if (disasmMode==XBinary::DM_M6809)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6809),pHandle);
    else if (disasmMode==XBinary::DM_M6811)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6811),pHandle);
    else if (disasmMode==XBinary::DM_CPU12)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_CPU12),pHandle);
    else if (disasmMode==XBinary::DM_HD6301)        result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6301),pHandle);
    else if (disasmMode==XBinary::DM_HD6309)        result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_6309),pHandle);
    else if (disasmMode==XBinary::DM_HCS08)         result=cs_open(CS_ARCH_M680X,cs_mode(CS_MODE_M680X_HCS08),pHandle);
//    else if (disasmMode==XBinary::DM_EVM)           error=cs_open(CS_ARCH_M680X,cs_mode(CS_ARCH_EVM),pHandle);
//    else if (disasmMode==XBinary::DM_MOS65XX)       error=cs_open(CS_ARCH_M680X,cs_mode(CS_ARCH_MOS65XX),pHandle);

    if(result==CS_ERR_OK)
    {
        if(bDetails)
        {
            cs_option(*pHandle,CS_OPT_DETAIL,CS_OPT_ON);
        }

        // TODO Syntax
    }
    else
    {
        *pHandle=0;
    }

    return result;
}

cs_err XCapstone::closeHandle(csh *pHandle)
{
    cs_err result=CS_ERR_HANDLE;

    if(*pHandle)
    {
        result=cs_close(pHandle);
        *pHandle=0;
    }

    return result;
}

XCapstone::DISASM_STRUCT XCapstone::disasm(csh handle, qint64 nAddress, char *pData, int nDataSize)
{
    DISASM_STRUCT result={};

    cs_insn *pInsn=0;

    int nNumberOfOpcodes=cs_disasm(handle,(uint8_t *)pData,nDataSize,nAddress,1,&pInsn);
    if(nNumberOfOpcodes>0)
    {
        result.nAddress=nAddress;
        result.nSize=pInsn->size;

        QString sMnemonic=pInsn->mnemonic;
        QString sStr=pInsn->op_str;

        result.sString+=sMnemonic;

        if(sStr!="") result.sString+=QString(" %1").arg(sStr);

        cs_free(pInsn,nNumberOfOpcodes);
    }

    return result;
}

bool XCapstone::isJmpOpcode(quint16 nOpcodeID)
{
    // TODO
    bool bResult=false;

    if( (nOpcodeID==X86_INS_JMP)||
        (nOpcodeID==X86_INS_JA)||
        (nOpcodeID==X86_INS_JAE)||
        (nOpcodeID==X86_INS_JB)||
        (nOpcodeID==X86_INS_JBE)||
        (nOpcodeID==X86_INS_JCXZ)||
        (nOpcodeID==X86_INS_JE)||
        (nOpcodeID==X86_INS_JECXZ)||
        (nOpcodeID==X86_INS_JG)||
        (nOpcodeID==X86_INS_JGE)||
        (nOpcodeID==X86_INS_JL)||
        (nOpcodeID==X86_INS_JLE)||
        (nOpcodeID==X86_INS_JNE)||
        (nOpcodeID==X86_INS_JNO)||
        (nOpcodeID==X86_INS_JNP)||
        (nOpcodeID==X86_INS_JNS)||
        (nOpcodeID==X86_INS_JO)||
        (nOpcodeID==X86_INS_JP)||
        (nOpcodeID==X86_INS_JRCXZ)||
        (nOpcodeID==X86_INS_JS)||
        (nOpcodeID==X86_INS_LOOP)||
        (nOpcodeID==X86_INS_LOOPE)||
        (nOpcodeID==X86_INS_LOOPNE)||
        (nOpcodeID==X86_INS_CALL))
    {
        bResult=true;
    }

    return bResult;
}

QString XCapstone::getSignature(QIODevice *pDevice, XBinary::_MEMORY_MAP *pMemoryMap, qint64 nAddress, ST signatureType, qint32 nCount)
{
    QString sResult;

    csh handle=0;

    openHandle(XBinary::getDisasmMode(pMemoryMap),&handle,true);

    if(handle)
    {
        while(nCount>0)
        {
            qint64 nOffset=XBinary::addressToOffset(pMemoryMap,nAddress);

            if(nOffset==-1)
            {
                break;
            }

            QByteArray baData=XBinary::read_array(pDevice,nOffset,15);

            cs_insn *pInsn=0;

            int nNumberOfOpcodes=cs_disasm(handle,(uint8_t *)baData.data(),15,nAddress,1,&pInsn);

            if(nNumberOfOpcodes>0)
            {
                quint32 nDispOffset=pInsn->detail->x86.encoding.disp_offset;
                quint32 nDispSize=pInsn->detail->x86.encoding.disp_size;
                quint32 nImmOffset=pInsn->detail->x86.encoding.imm_offset;
                quint32 nImmSize=pInsn->detail->x86.encoding.imm_size;

                baData.resize(pInsn->size);

                QString sHEX=baData.toHex().data();

                if((signatureType==ST_FULL)||(signatureType==ST_MASK))
                {
                    nAddress+=pInsn->size;

                    if(signatureType==ST_MASK)
                    {
                        if(nDispSize)
                        {
                            sHEX=replaceWild(sHEX,nDispOffset,nDispSize,'.');
                        }

                        if(nImmSize)
                        {
                            sHEX=replaceWild(sHEX,nImmOffset,nImmSize,'.');
                        }
                    }
                }
                else if(signatureType==ST_MASKREL)
                {
                    if(isJmpOpcode(pInsn->id))
                    {
                        // TODO another archs
                        for(int i=0; i<pInsn->detail->x86.op_count; i++)
                        {
                            if(pInsn->detail->x86.operands[i].type==X86_OP_IMM) // TODO another archs !!!
                            {
                                qint64 nImm=pInsn->detail->x86.operands[i].imm;

                                nAddress=nImm;

                                sHEX=replaceWild(sHEX,nImmOffset,nImmSize,'$');
                            }
                        }
                    }
                    else
                    {
                        nAddress+=pInsn->size;
                    }
                }

                sResult+=sHEX;

                cs_free(pInsn,nNumberOfOpcodes);
            }
            else
            {
                break;
            }

            nCount--;
        }

        closeHandle(&handle);
    }

    return sResult;
}

QString XCapstone::replaceWild(QString sString, qint32 nOffset, qint32 nSize, QChar cWild)
{
    QString sResult=sString;
    QString sWild;

    sWild=sWild.fill(cWild,nSize*2);

    sResult=sResult.replace(nOffset*2,nSize*2,sWild);

    return sResult;
}
