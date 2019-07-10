
# Copyright 2008-2019 Douglas Wikstrom
#
# This file is part of Verificatum Mix-Net (VMN).
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

AC_DEFUN([ACE_CHECK_LOADJAR],[
AC_REQUIRE([ACE_PROG_JAVA])

AC_ARG_ENABLE([check-$4],
     [  --disable-check-$4    Skip checking that $3 is installed.],
     [],[
ace_res=$($JAVA $JAVAFLAGS -classpath $2:tools/installation TestLoadJar $5 $6)

echo -n "checking for $3... "
if test "x$ace_res" = x;
then
   echo "yes"
else
   echo "no"
   AC_MSG_ERROR([$ace_res

Please make sure that $3 is installed
(visit https://www.verificatum.org) and its absolute path is provided
to configure as the value of the environment variable $1.

This is only needed to configure for compilation. This environment
variable is not needed after installation. In a typical installation
your configuration command should be:

$1=/usr/local/share/java/$3 ./configure --enable-$4
])
fi
])
])
