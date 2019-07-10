dnl Copyright 2008-2019 Douglas Wikstrom
dnl
dnl This file is part of Verificatum Mix-Net (VMN).
dnl
dnl Permission is hereby granted, free of charge, to any person
dnl obtaining a copy of this software and associated documentation
dnl files (the "Software"), to deal in the Software without
dnl restriction, including without limitation the rights to use, copy,
dnl modify, merge, publish, distribute, sublicense, and/or sell copies
dnl of the Software, and to permit persons to whom the Software is
dnl furnished to do so, subject to the following conditions:
dnl
dnl The above copyright notice and this permission notice shall be
dnl included in all copies or substantial portions of the Software.
dnl
dnl THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
dnl MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
dnl BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
dnl ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
dnl CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
dnl SOFTWARE.
dnl
ifdef(`USE_VMGJ',`define(`VMGJ_CODE')',`define(`VMGJ_PURE_JAVA_CODE')')dnl
ifdef(`USE_VECJ',`define(`VECJ_CODE')',`define(`VECJ_PURE_JAVA_CODE')')dnl
dnl
ifdef(`VMGJ_PURE_JAVA_CODE',dnl
`define(`VMGJ_BEGIN',`Removed native code here.divert(-1)')dnl
define(`VMGJ_END',`divert')dnl
define(`VMGJ_PURE_JAVA_BEGIN',`Enabled pure java code begins here.')dnl
define(`VMGJ_PURE_JAVA_END',`Enabled pure java code ends here')')dnl
dnl
ifdef(`VMGJ_CODE',dnl
`define(`VMGJ_PURE_JAVA_BEGIN',`Removed pure java code here.divert(-1)')dnl
define(`VMGJ_PURE_JAVA_END',`divert')dnl
define(`VMGJ_BEGIN',`Enabled calls to native code begins here.')dnl
define(`VMGJ_END',`Enabled calls to native code ends here')')dnl
dnl
ifdef(`VECJ_PURE_JAVA_CODE',dnl
`define(`VECJ_BEGIN',`Removed native code here.divert(-1)')dnl
define(`VECJ_END',`divert')dnl
define(`VECJ_PURE_JAVA_BEGIN',`Enabled pure java code begins here.')dnl
define(`VECJ_PURE_JAVA_END',`Enabled pure java code ends here')')dnl
dnl
ifdef(`VECJ_CODE',dnl
`define(`VECJ_PURE_JAVA_BEGIN',`Removed pure java code here.divert(-1)')dnl
define(`VECJ_PURE_JAVA_END',`divert')dnl
define(`VECJ_BEGIN',`Enabled calls to native code begins here.')dnl
define(`VECJ_END',`Enabled calls to native code ends here')')dnl
dnl
undefine(`format')dnl
