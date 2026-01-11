/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
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
#ifndef XCAPSTONE_H
#define XCAPSTONE_H

#include "capstone/capstone.h"
#include "xbinary.h"
#ifdef QT_GUI_LIB
#include <QColor>
#endif

class XCapstone : public QObject {
    Q_OBJECT

public:
    // TODO error,info signals
    // TODO non static
    explicit XCapstone(QObject *pParent = nullptr);

    static bool isModeValid(XBinary::DM disasmMode);
    static cs_err openHandle(XBinary::DM disasmMode, csh *pHandle, bool bDetails, XBinary::SYNTAX syntax = XBinary::SYNTAX_DEFAULT);
    static cs_err closeHandle(csh *pHandle);

    static void printEnabledArchs();

private:
    static const qint32 N_OPCODE_SIZE = 16;  // mb TODO rename set/get
};

#endif  // XCAPSTONE_H
