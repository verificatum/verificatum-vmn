

                  VERIFICATUM MIX-NET (VMN)


VMN is an implementation of a provably secure mix-net, but the
framework is quite general and several of the subprotocols are useful
without any changes to implement other complex protocols. The software
is modular and well documented to allow easy use and verification. For
comprehensive information and documentation we refer the reader to
<https://www.verificatum.org>.

For improved efficiency, the most time critical parts can optionally
be linked to routines in:

* The GNU MP library (GMP) and the GMP Modular Exponentiation
  Extension (GMPMEE) library, using Verificatum Multiplicative
  Group library for Java (VMGJ),

* The Verificatum Elliptic Curve library (VEC), using the Verificatum
  Elliptic Curve library for Java (VECJ), which is based on the GNU MP
  library (GMP).

The overhead for making native calls is very small in the context of
modular exponentiations and scalar multiplications in elliptic
curves. Thus, this makes VMN almost as fast as if it was implemented
directly in C while keeping the simplicity of Java code for the
protocol logic.

The following assumes that you are using a release. Developers should
also read README_DEV.


                       QUICK START

On most UN*X systems you can simply configure everything, build and
install using the following snippet, but we strongly advice against
this in real applications unless it has already been verified to be
adequate on your platform and in your application.

        $ ./configure
        $ make
        $ sudo make install

If the optimized native code is used, then ./configure would be
replaced by

        $ LD_LIBRARY_PATH=/usr/local/lib \
VMGJ_JAR=/usr/local/share/java/verificatum-vmgj-<VMGJ_VERSION>.jar \
VECJ_JAR=/usr/local/share/java/verificatum-vecj-<VECJ_VERSION>.jar \
./configure --enable-vmgj --enable-vecj

This assumes that you did a corresponding standard installation of
GMPMEE, VMGJ, VEC, and VECJ.

We stress that it does NOT suffice to put the jars in the
CLASSPATH. The jars used are hardcoded into the executable scripts to
reduce the risk of relying on outdated versions. The configure script
matches the version given in the manifest file of each jar.


                         BUILDING

1) You need to install Open JDK 7 (or later) and M4.

2) Please use

        $ ./configure
        $ make

   to build the software.

3) If you want to use native code for modular exponentiations etc,
   then you must install GMP, GMPMEE, VMGJ, VEC, and VECJ first. We
   refer the user to the installation instructions of these
   packages. Depending on your operating system, GMP may already be
   installed. Make sure that it is a recent version, since some
   distributions of operating systems use outdated versions.

   Set the environment variables VMGJ_JAR and VECJ_JAR to the absolute
   paths of the jar files of VMGJ and VECJ.

   Note that for security reasons the versions of these libraries must
   match those in configure.ac *exactly* and that it does not suffice
   to rename the jar files to pass the configuration tests.

   Then the configure command above must be replaced by

        $ ./configure --enable-vmgj --enable-vecj

   to enable use of the native code instead of the pure Java code. You
   can of course use one of the libraries without the other, but in
   both cases you need to install GMP.

   On most platforms the following will work

        $ LD_LIBRARY_PATH=/usr/local/lib \
VMGJ_JAR=/usr/local/share/java/verificatum-vmgj-<VERSION>.jar \
VECJ_JAR=/usr/local/share/java/verificatum-vecj-<VERSION>.jar \
./configure --enable-vmgj --enable-vecj

   The configure script tries to guess the locations of jni.h and
   jni_md.h, but you may need to set up C_INCLUDE_PATH on your own if
   this fails or if you want to use a specific JVM.

4) Optionally, you may run a few unit tests, by

        $ make check

   This takes some time, since it verifies both basic functionality as
   well as runs some of the subprotocols in a simulated environment
   and some of these tests necessarily use almost realistic data
   sizes.


			INSTALLING

   ##########################################################
   ##################### WARNING! ###########################
   ##########################################################
   #                                                        #
   # WARNING! Please read the following instructions        #
   # carefully. Failure to do so may result in a completely #
   # insecure installation.                                 #
   #                                                        #
   ##########################################################


1) Please use

        $ make install

   to install the software. You may need to be root or use sudo.

2) The tools in the library, e.g., vog, that require a source of
   randomness to function, uses the random source defined by two files
   that by default are named:

       $HOME/.verificatum_random_source

       $HOME/.verificatum_random_seed

   The first stores a description of a random device or a PRG and the
   second stores a random seed if a PRG is used.

   Here $HOME denotes the home directory of the current user. The
   command vog is a script that invokes the java interpreter on the
   class verificatum.ui.gen.GeneratorTool.

   You may override the location of these files by setting the
   environment variables:

       VERIFICATUM_RANDOM_SOURCE
       VERIFICATUM_RANDOM_SEED

   ##########################################################
   ##################### WARNING! ###########################
   ##########################################################
   #                                                        #
   # If an adversary is able to write to any of these       #
   # files, then the software provides no security at all.  #
   #                                                        #
   # If an adversary is able to read from the second file,  #
   # then the software provides no security at all. The     #
   # contents of the first file can safely be made public.  #
   #                                                        #
   # If you use the environment variables, then you must    #
   # make sure that nobody can modify them.
   #                                                        #
   ##########################################################


3) The above two files must be initialized using vog before any
   commands that require randomness are used. You can do this as
   follows.

       $ vog -rndinit RandomDevice <my device>
       Successfully initialized random source!

   If you wish to use a PRG instead, then you need to provide a seed
   as well, e.g., to use a provably secure PRG under the DDH
   assumption you could execute:

       $ vog -rndinit -seed seedfile PRGElGamal -fixed 1024
       Successfully initialized random source! Deleted seed file.

   The command replaces the seed file each time it is invoked to avoid
   accidental reuse.

   If you wish to change the random source you need to remove the
   files that store the random source and initialize it again with
   your new choice.

   ##########################################################
   ##################### WARNING! ###########################
   ##########################################################
   #                                                        #
   # The provided seed file must contain bits that are      #
   # indistinguishable from truly random bits. The seed     #
   # bits must not be reused here or anywhere else.         #
   #                                                        #
   # Failure to provide a proper seed file may result in a  #
   # catastrophic security breach.                          #
   #                                                        #
   ##########################################################


			 USING

Comprehensive documentation ready for printing can be downloaded at
<https://www.verificatum.org>, but you can also go directly to
demo/mixnet and run the ./demo script if you are impatient. The README
in this directory explains how to configure the demo.

Technical information can, after installing, be found by using

        $ vtm -h

which gives an overview of the available commands. More information
about each command can then be printed.


                   API DOCUMENTATION

You may use
 
        $ make api

to invoke Javadoc to build the API. The API is not installed
anywhere. You can copy it to any location.


                     REPORTING BUGS

Minor bugs should be reported in the repository system as issues or
bugs. Security critical bugs, vulnerabilities, etc should be reported
directly to Verificatum AB. We will make best effort to disclose the
information in a responsible way before the finder gets proper credit.