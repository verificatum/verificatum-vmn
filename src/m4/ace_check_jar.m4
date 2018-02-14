
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

AC_DEFUN([ACE_CHECK_JAR],[

AC_ARG_ENABLE([$5],
     [  --enable-$5    Use $3.],
     [case "${enableval}" in
       yes) $5=true ;

            # Checks for libraries.
            ACE_CHECK_LOADJAR([$2],[$3],[$4],[$5],[$6],[$7])

	    # Set the path to the jar.
	    AC_SUBST($2,[$3]);;

       no)  $5=false ;;
      esac],[$5=false])
AM_CONDITIONAL([$1], [test x$$5 = xtrue])

])
