// copyright (c) 2019 hors<horsicq@gmail.com>
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

XCapstone::XCapstone(QObject *parent) : QObject(parent)
{

}

QString XCapstone::disasm(csh handle, qint64 nAddress, char *pData, int nDataSize)
{
    QString sResult;

    cs_insn *insn;

    int count=cs_disasm(handle,(uint8_t *)pData,nDataSize,nAddress,1,&insn);
    if(count>0)
    {
        QString sMnemonic=insn->mnemonic;
        QString sStr=insn->op_str;

        sResult+=sMnemonic;

        if(sStr!="")
        {
            sResult+=QString(" %1").arg(sStr);
        }

        cs_free(insn, count);
    }

    return sResult;
}
