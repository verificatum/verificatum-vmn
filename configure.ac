
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

AC_PREREQ([2.63])
AC_INIT([verificatum-vmn],
        [m4_esyscmd([m4 .version.m4])],
        [info@verificatum.com])
AC_CANONICAL_SYSTEM # Must appear before AM_INIT_AUTOMAKE
AM_INIT_AUTOMAKE([foreign tar-ustar -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])

# We require a specific version of VCR. The version is verified both in
# terms of the name of the jar file and the contents of the jar
# manifest file.
VCR_VERSION=3.0.3

# Checks for development tools we need.
ACE_PROG_JAVAC
ACE_PROG_JAR
ACE_PROG_JAVADOC
ACE_PROG_JAVA

cd tools/installation
javac TestLoadJar.java
cd -

# We need to figure out if we need to pass -J-d64 to javac.
AM_CONDITIONAL([BITS64], [test x`getconf LONG_BIT` = x64])

AC_CONFIG_FILES([Makefile])

AC_SUBST([VCR_COMPLETE_VERSION],[`vcr-${VCR_VERSION}-info complete`])

if test x = x${VCR_JAR};
then
    AC_SUBST([VCR_JAR],`vcr-${VCR_VERSION}-info jar`)
fi

if test x = x${LD_LIBRARY_PATH};
then
    AC_SUBST([LD_LIBRARY_PATH_VCR],`vcr-${VCR_VERSION}-info lib`)
fi

# Check that the right version of VCR is installed.
ACE_CHECK_JAR([VCR],
              [VCR_JAR],
              [${VCR_JAR}],
              [verificatum-vcr-${VCR_VERSION}.jar],
              [vcr],
              [com.verificatum.Verificatum],
              [${VCR_VERSION}])

AC_OUTPUT
