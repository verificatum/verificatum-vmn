# Additional Information for Developers

When you start from the actual repository source and not a
distribution you can use

        make -f Makefile.build

to run the necessary `libtool`, `autoconf`, etc routines and copy a
few additional M4 scripts to the right place to put the directory in a
similar state to that of a distribution directory. Then you can run
the usual `./configure; make; sudo make install`.

If the state of the directory is messed up, then you can run

        make -f Makefile.build clean

to do a brutal cleanup of everything. Yes, there are various clean
commands in Makefile, but this seems more robust and convenient when
developing. Finally, you can use

        make -f Makefile.build dist

to build a distribution tar.gz-ball in a single command. This merely
sets up things and then runs the usual `make dist`.


## Static Analysis

We currently use three different static analyzers: Checkstyle,
FindBugs, and PMD. To encapsulate installation hazzle on some
platforms and adapt to changes, we use them through wrappers and
filters contained in subdirectories of the tools-directory. This is
also where their configuration files are found, and where reports go
when performing the analysis.

You can either run a single tool, e.g.,

        make checkstyle

(or correspondingly with "findbugs" or "pmd") and your report will end
up in `tools/staticanalysis/checkstyle/checkstyle_report.txt` (or
similarly for FindBugs and PMD), or you can generate an aggregate
report using

        make analysis

which ends up in `tools/staticanalysis/analysis_report.txt`.

Any set of style rules is somewhat arbitrary, and there are silly
rules, but fixing any such problems only takes a couple of minutes and
makes it easier to identify real issues if the code is consistent.

Real issues must either be resolved, or examined carefully and handled
using the rules or inline suppressions.
