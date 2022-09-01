
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

AC_PREREQ([2.71])
AC_INIT([verificatum-vmn],[m4_esyscmd([m4 .version.m4])],[info@verificatum.com])
AC_CANONICAL_TARGET # Must appear before AM_INIT_AUTOMAKE
AM_INIT_AUTOMAKE([foreign tar-ustar -Wall -Werror -Wno-portability])
AC_CONFIG_MACRO_DIR([m4])

# We require a specific version of VCR. The version is verified both in
# terms of the name of the jar file and the contents of the jar
# manifest file.
VCR_VERSION=3.0.4

# Checks for development tools we need.
ACE_PROG_JAVAC
ACE_PROG_JAR
ACE_PROG_JAVADOC
ACE_PROG_JAVA

cd tools/installation
javac TestLoadJar.java
cd -

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
