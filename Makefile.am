
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

.PHONY: clean cleanfindbugs cleancheckstyle cleanpmd cleananalysis cleanapi check runtests rundemos

ACLOCAL_AMFLAGS=-I m4

##################### Variables used by Automake ############################

jardir = $(datadir)/java

# libdir is defined by Autoconf.

########################## Custom variables #################################

CWD = $(shell pwd)
SRC = src
PKGPATH = $(SRC)/java
MFSRC = $(SRC)/mf
APIROOT = api
JARFILE = $(PACKAGE)-$(VERSION).jar
VMN_JAR = $(jardir)/$(JARFILE)
ALL_JAR = $(VCR_JAR):$(VMN_JAR)
CLASSESROOT = classes
CLASSPATH := .:$(CLASSESROOT):$(JARFILE):$(VCR_JAR):$(CLASSPATH)
BINDIR = bin
SRC_BINDIR = $(SRC)/bin
STATANA = tools/staticanalysis
INSTA = tools/installation
TMP_TEST_DIR = .tmp_test_dir
TMP_DEMO_DIR = .tmp_demo_dir
JDK_DOC="http://docs.oracle.com/javase/8/docs/api"

# Guess that lib files for dependencies are in the same place as
# configured for this installation.
export LD_LIBRARY_PATH := $(libdir):$(LD_LIBRARY_PATH)

COMPLETE_VERSION=vmn-$(VERSION)($(VCR_COMPLETE_VERSION))

######################## Extracting targets  ################################

# Space separated list of all Java source filenames (both existing and
# those to be generated).
FILES_JAVANAMES = $(shell find $(PKGPATH) -name "*.java" \
| sort | uniq | tr "\n" " ")

# Executable wrapper scripts.
FILES_SCRIPT = $(shell find $(SRC_BINDIR) -name "*.src" \
| grep -v vmn-info \
| sed -e s£\\.src££g | sed -e s£$(SRC_BINDIR)£$(BINDIR)£ | tr "\n" " ")

# Space separated list of all test classes implementing unit tests.
TEST_CLASSNAMES = $(shell find $(PKGPATH) -name "*.java" -o -name "*.magic" \
| sed -e "s£$(PKGPATH)/££g" | sed -e "s/\//./" \
| grep ".Test" | grep -v ".test." \
| sed -e s£\\.java££g | sed -e s£\\.magic££g | sed -e s£/£\\.£g \
| sort | uniq | tr "\n" " ")

# Space separated list of all demo classes implementing unit tests of
# protocols. We list them manually to execute them in the right order.
DEMO_CLASSNAMES = \
com.verificatum.protocol.distr.DemoPlainKeys \
com.verificatum.protocol.secretsharing.DemoPedersen \
com.verificatum.protocol.secretsharing.DemoPedersenSequential \
com.verificatum.protocol.distr.DemoIndependentGenerator \
com.verificatum.protocol.distr.DemoDKG \
com.verificatum.protocol.elgamal.DemoDistrElGamal \
com.verificatum.protocol.coinflip.DemoCoinFlipPRingSource \
com.verificatum.protocol.distr.DemoIndependentGeneratorsI \
com.verificatum.protocol.mixnet.DemoShufflerElGamal \
com.verificatum.protocol.hvzk.DemoPoSCTW \
com.verificatum.protocol.mixnet.DemoPermutationCommitment \
com.verificatum.protocol.mixnet.DemoMixNetElGamal


############################## Compiling ####################################

all: $(JARFILE)

# Jar manifest.
$(CLASSESROOT)/MANIFEST.MF: $(MFSRC)/MANIFEST.MF.src
	mkdir -p $(@D)
	cat .macros.m4 $(MFSRC)/MANIFEST.MF.src | m4 > $(CLASSESROOT)/MANIFEST.MF

# Create the destination directory.
.classesroot.stamp:
	mkdir -p $(CLASSESROOT)
	@touch .classesroot.stamp

# Compile all Java files.
.classes.stamp: .classesroot.stamp $(FILES_JAVANAMES)
	$(JAVAC) -version
	$(JAVAC) -Xlint:unchecked -classpath $(CLASSPATH) -d $(CLASSESROOT) $(AM_JAVACFLAGS) $(JAVACFLAGS) $(FILES_JAVANAMES)
	@touch .classes.stamp

# Build JAR file.
jar : $(JARFILE)
$(JARFILE): .classes.stamp $(FILES_TXT) $(CLASSESROOT)/MANIFEST.MF
	cd $(CLASSESROOT); $(JAR) cfm $@ MANIFEST.MF com; cp $@ ..

$(BINDIR)/vmn-$(VERSION)-info: scriptmacros.m4 $(SRC_BINDIR)/vmn-info.src
	mkdir -p $(BINDIR)
	cat scriptmacros.m4 $(SRC_BINDIR)/vmn-info.src | m4 > $(BINDIR)/vmn-$(VERSION)-info
	chmod +x $(BINDIR)/vmn-$(VERSION)-info

# Additional flags for the JVM.  Amount of memory used by the JVM. Our
# software execute in less than 2GB, so this is conservative.
# JVM_FLAGS=-Xms1024m -Xmx6000m
JVM_FLAGS=

scriptmacros.m4:
	@printf "define(M4_JVM_FLAGS, $(JVM_FLAGS))dnl\n" > scriptmacros.m4
	@printf "define(M4_VERSION, $(VERSION))dnl\n" >> scriptmacros.m4
	@printf "define(M4_COMPLETE_VERSION, $(COMPLETE_VERSION))dnl\n" >> scriptmacros.m4
	@printf "define(M4_BINDIR, $(bindir))dnl\n" >> scriptmacros.m4
	@printf "define(M4_LIBDIR, $(libdir))dnl\n" >> scriptmacros.m4
	@printf "define(M4_ALL_JAR, $(ALL_JAR))dnl\n" >> scriptmacros.m4
	@printf "define(M4_VERIFICATUM_VOG_BUILTIN, $(BCVOG))dnl\n" >> scriptmacros.m4
	@printf "define(M4_JAVA_FLAGS, \`$(JAVA_FLAGS)')" >> scriptmacros.m4

$(FILES_SCRIPT): $(BINDIR)/%: $(SRC_BINDIR)/%.src scriptmacros.m4
	mkdir -p $(BINDIR)
	cat scriptmacros.m4 $(SRC_BINDIR)/$*.src | m4 > $@
	chmod +x $@

########################## Static analysis ##################################

# Edit the wrappers in the subdirectories of $(STATANA) if needed.

# Do a Checkstyle analysis of the source and save the result in
# $(STATANA)/checkstyle/checkstyle_report.txt.
checkstyle: $(STATANA)/checkstyle/checkstyle_report.txt $(STATANA)/checkstyle/checkstyle_filter.sh
$(STATANA)/checkstyle/checkstyle_report.txt: $(JARFILE)
	rm -f $(STATANA)/checkstyle/checkstyle_report_tmp.txt
	cd $(STATANA)/checkstyle; ./checkstyle_wrapper checkstyle_configure.xml checkstyle_raw_report.txt $(CWD)/$(PKGPATH); ./checkstyle_filter.sh checkstyle_raw_report.txt checkstyle_report.txt

# Do a Findbugs analysis of the jar and save the result in
# $(STATANA)/findbugs/findbugs_report.txt. Findbugs does not
# provide any proper way of installation. The
# $(STATANA)/findbugs/findbugs_wrapper tries to find the directory
# named findbugs-?-?-? for the most recent version. If no such
# directory exists, then it tries the same in the home directory. Edit
# the wrapper if needed.
findbugs: $(STATANA)/findbugs/findbugs_report.txt
$(STATANA)/findbugs/findbugs_report.txt: $(JARFILE)
	./$(STATANA)/findbugs/findbugs_wrapper -textui -exclude $(STATANA)/findbugs/findbugs_configure.xml -auxclasspath $(CLASSPATH) $(JARFILE) > $(STATANA)/findbugs/findbugs_report.txt

# Do a PMD analysis of the source and save the result in
# $(STATANA)/pmd/pmd_report.txt. PMD does not provide any proper
# way of installation. The $(STATANA)/pmd/pmd_wrapper tries to
# find the directory named pmd-bin-?-?-? for the most recent
# version. If no such directory exists, then it tries the same in the
# home directory. Edit the wrapper if needed.
pmd: $(STATANA)/pmd/pmd_report.txt
$(STATANA)/pmd/pmd_report.txt: $(JARFILE)
	./$(STATANA)/pmd/pmd_wrapper -rulesets $(STATANA)/pmd/pmd_ruleset.xml -d $(PKGPATH) | sed "s/.*verificatum\/\(com\/verificatum.*\)/\1/p" | uniq > $(STATANA)/pmd/pmd_raw_report.txt
	cd $(STATANA)/pmd; ./pmd_filter.sh pmd_raw_report.txt pmd_report.txt

# Execute all static analyzers.
analysis: checkstyle findbugs pmd $(STATANA)/generate_analysis.sh
	cd $(STATANA); ./generate_analysis.sh
	cat $(STATANA)/analysis_report.txt

# Build api.
api: $(JARFILE)
	javadoc -classpath $(CLASSPATH) -d $(APIROOT) -link $(JDK_DOC) $(FILES_JAVANAMES)

######################### Installation targets ##############################

install-data-hook:
	@echo ""
	@echo "================================================================"
	@echo ""
	@echo "                   DOCUMENTATION"
	@echo ""
	@echo " Please consult the README.md file before using the software."
	@echo " There is also comprehensive documentation in the form of"
	@echo " white papers at https://www.verificatum.org."
	@echo ""
	@echo " You can list the main available commands using the umbrella"
	@echo " command"
	@echo ""
	@echo "     $$ vtm -h"
	@echo ""
	@echo " and then move on to read the usage information for each "
	@echo " individual command."
	@echo ""
	@echo " The mix-net comes with a well documented demonstrator which"
	@echo " can be configured in many ways to illustrate the features of"
	@echo " the mix-net. The demo is found in ./demo/mixnet. See the"
	@echo " README.md file in this directory for more information."
	@echo ""
	@echo "================================================================"
	@echo ""

dist_noinst_DATA = demo $(PKGPATH) README.md .macros.m4 .version.m4 tools $(SRC)
jar_DATA = $(JARFILE)
dist_bin = $(FILES_SCRIPT) $(BINDIR)/vmn-$(VERSION)-info
dist_bin_SCRIPTS = $(FILES_SCRIPT) $(BINDIR)/vmn-$(VERSION)-info


############################# Testing #######################################

# There are three types of tests:
#
# Unit tests that checks functionality of classes that do not require
# any interaction with other parties. The names of such classes starts
# with "Test" (typically followed by the class that is tested). The
# command line tool for executing the tests implemented in a given
# test class is "vtest".
#
# Tests that verifies the functionality of protocols (that do require
# interaction). The names of such classes start with "Demo". The
# command line tool for executing the demo implemented in a given
# demo class is "vdemo". If there is any problem when "make check" is
# executed, then the command line tools can be used to debug a single
# test/demo separately. Use the "-h" option to learn about the options
# accepted by the tools.

check: runtests rundemos runmixnet

# Verifying non-interactive classes.
runtests: .classes.stamp
	@rm -rf $(TMP_TEST_DIR)
	@mkdir -p $(TMP_TEST_DIR)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) CLASSPATH=$(CLASSPATH) vtest -exec $(TEST_CLASSNAMES)
	@rm -rf $(TMP_TEST_DIR)

# Verifying protocols.
rundemos: $(BINDIR)/vdemo .classes.stamp
	@rm -rf $(TMP_DEMO_DIR)
	@mkdir -p $(TMP_DEMO_DIR)
	@LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) CLASSPATH=$(CLASSPATH) $(BINDIR)/vdemo -hide -demoroot $(TMP_DEMO_DIR) $(DEMO_CLASSNAMES)
	@rm -rf $(TMP_DEMO_DIR)

# Verifying mix-net.
runmixnet: $(FILES_SCRIPT) .classes.stamp
	@cd demo/mixnet; ./check

############################# Cleaning ######################################

cleanapi:
	rm -rf $(APIROOT)

cleancheckstyle:
	rm -rf $(STATANA)/checkstyle/checkstyle_raw_report.txt $(STATANA)/checkstyle/checkstyle_report.txt

cleanfindbugs:
	rm -rf $(STATANA)/findbugs/findbugs_report.txt

cleanpmd:
	rm -rf $(STATANA)/pmd/pmd_report.txt $(STATANA)/pmd/pmd_raw_report.txt

cleananalysis: cleancheckstyle cleanfindbugs cleanpmd
	rm -rf $(STATANA)/analysis_report.txt

clean-local: cleanapi cleananalysis
	find . -name "*~" -delete
	@rm -rf verificatum-vmn*.tar $(INSTA)/*.class $(FILES_SCRIPT) scriptmacros.m4 $(JARFILE) $(TMP_TEST_DIR) $(TMP_DEMO_DIR) $(APIROOT) $(CLASSESROOT) *.stamp .*.stamp compile $(BINDIR)/vmn-$(VERSION)-info
