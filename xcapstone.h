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
#ifndef XCAPSTONE_H
#define XCAPSTONE_H

#include "xbinary.h"
#include "capstone/capstone.h"

class XCapstone : public QObject
{
    Q_OBJECT

public:

    struct DISASM_STRUCT
    {
        qint64 nAddress;
        QString sString;
        qint64 nSize;
    };

    enum ST
    {
        ST_UNKNOWN=0,
        ST_FULL,
        ST_MASK,
        ST_MASKREL
    };

    // TODO error
    explicit XCapstone(QObject *pParent=nullptr);
    static cs_err openHandle(XBinary::DM disasmMode,csh *pHandle,bool bDetails);
    static cs_err closeHandle(csh *pHandle);
    static DISASM_STRUCT disasm(csh handle,qint64 nAddress,char *pData,int nDataSize);
    static bool isJmpOpcode(quint16 nOpcodeID);
    static QString getSignature(QIODevice *pDevice,XBinary::_MEMORY_MAP *pMemoryMap,qint64 nAddress,ST signatureType,qint32 nCount);
    static QString replaceWild(QString sString,qint32 nOffset,qint32 nSize,QChar cWild);
};

#endif // XCAPSTONE_H
