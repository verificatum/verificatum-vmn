dnl Copyright 2008-2018 Douglas Wikstrom
dnl
dnl This file is part of Verificatum Mix-Net (VMN).
dnl
dnl VMN is free software: you can redistribute it and/or modify it under
dnl the terms of the GNU Affero General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl VMN is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
dnl or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
dnl Public License for more details.
dnl
dnl You should have received a copy of the GNU Affero General Public
dnl License along with VMN. If not, see <http://www.gnu.org/licenses/>.
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
