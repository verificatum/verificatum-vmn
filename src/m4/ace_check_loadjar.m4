
# Copyright 2008-2018 Douglas Wikstrom
#
# This file is part of Verificatum Mix-Net (VMN).
#
# VMN is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# VMN is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
# Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with VMN. If not, see <http://www.gnu.org/licenses/>.

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
