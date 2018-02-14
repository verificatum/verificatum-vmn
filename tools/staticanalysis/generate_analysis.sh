#!/bin/sh

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


add_result() {

    TOOLNAME=$1
    CONTENTFILE=$2
    OUTPUTFILE=$3

    printf "\n#########################################################\n" \
>> $OUTPUTFILE
    printf "$TOOLNAME\n\n" >> $OUTPUTFILE

    CONTENT=`cat $CONTENTFILE`

    if test "x$CONTENT" = x;
    then
	printf "NO COMPLAINTS!\n" >> $OUTPUTFILE
    else
	printf "%s" "$CONTENT" >> $OUTPUTFILE
    fi
}

printf "\nCODE ANALYSIS REPORTS\n" > analysis_report.txt
add_result "Checkstyle (configured using checkstyle_ruleset.xml and checkstyle_suppressions.xml)" checkstyle/checkstyle_report.txt analysis_report.txt
add_result "Findbugs (configured using findbugs_configure.xml)" findbugs/findbugs_report.txt analysis_report.txt
add_result "PMD (configured using pmd_ruleset.xml and pmd_filter.sh)" pmd/pmd_report.txt analysis_report.txt

printf "\n"
