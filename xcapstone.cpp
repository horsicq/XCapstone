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

QString XCapstone::disasm(csh handle, qint64 nAddress, char *pData, int nDataSize)
{
    QString sResult;

    cs_insn *pInsn=0;

    int nNumberOfOpcodes=cs_disasm(handle,(uint8_t *)pData,nDataSize,nAddress,1,&pInsn);
    if(nNumberOfOpcodes>0)
    {
        QString sMnemonic=pInsn->mnemonic;
        QString sStr=pInsn->op_str;

        sResult+=sMnemonic;

        if(sStr!="") sResult+=QString(" %1").arg(sStr);

        cs_free(pInsn, nNumberOfOpcodes);
    }

    return sResult;
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
