# Verificatum Mix-Net (VMN)

## Overview

VMN was completed 2008 and is the first implementation of a fully
distributed and provably secure mix-net. It is also the first
implementation of a universally verifiable mix-net and the first with
a serious benchmark.

However, the framework is quite general and several of
the subprotocols are useful without any changes to implement other
complex protocols.

The software is modular and well documented to allow easy use and
verification. For comprehensive information and documentation we refer
the reader to https://www.verificatum.org.


## Quick Start

An installation package is available at https://www.verificatum.org
that contains, and compiles and installs all needed software to run a
demonstrator in a single command. This is the recommended solution to
get started.


## Building

Depending on how the underlying [Verificatum Core
Routines](https://github.com/verificatum/verificatum-vmn) library is
compiled, native code may be used. You can check this using

        vcr-<VCR_VERSION>-info complete

where `<VCR_VERSION>` is the version of the VCR library. Type `vcr-`
and then use tab to get the rest of the command to execute. In any
case this library is a requirement to install VMN.

1. You need to install Open JDK 10 (or later) and M4.

2. Please use

        ./configure
        make

   to build the software.

3. If you want to use native code for modular exponentiations etc,
   then you must build VCR with native code enabled and install it in
   that way. You may inspect the complete version of VCR you are using
   with the following command, where `<VCR_VERSION>` is your version
   of VCR.

        vcr-<VCR_VERSION>-info complete

4. Optionally, you may run unit tests:

        make check

   This takes some time, since it verifies both basic functionality as
   well as run some of the subprotocols in a simulated environment and
   some of these tests necessarily use almost realistic data sizes.


## Installing

   **WARNING! Please read the following instructions
     carefully. Failure to do so may result in a completely insecure
     installation.**

1. Please use

        make install

   to install the software. You may need to be root or use sudo.

2. The tools in the library, e.g., vog, that require a source of
   randomness to function, uses the random source defined by two files
   that by default are named:

       $HOME/.verificatum_random_source
       $HOME/.verificatum_random_seed

   The first stores a description of a random device or a PRG and the
   second stores a random seed if a PRG is used.

   Here `$HOME` denotes the home directory of the user. The command
   vog is a script that invokes the java interpreter on the class
   `com.verificatum.ui.gen.GeneratorTool`.

   You may override the location of these files by setting the
   environment variables:

       VERIFICATUM_RANDOM_SOURCE
       VERIFICATUM_RANDOM_SEED

   **WARNING!**

   **If an adversary is able to write to any of these files, then the
     software provides no security at all.**

   **If an adversary is able to read from the second file, then the
     software provides no security at all. The contents of the first
     file can safely be made public if it cannot be changed.**

   **If you use the environment variables, then you must make sure
     that nobody can modify them.**

   **Please understand that this software is meant to be run in a
     secure environment. You are responsible for providing this
     environment.**

3. The above two files must be initialized using vog before any
   commands that require randomness are used. You can do this as
   follows.

       vog -rndinit RandomDevice <my device>
       Successfully initialized random source!

   If you wish to use a PRG instead, then you need to provide a seed
   as well, e.g., to use a provably secure PRG under the DDH
   assumption you could execute:

       vog -rndinit -seed seedfile PRGElGamal -fixed 1024
       Successfully initialized random source! Deleted seed file.

   The command replaces the seed file each time it is invoked to avoid
   accidental reuse.

   If you wish to change the random source you need to remove the
   files that store the random source and initialize it again with
   your new choice.

   **WARNING!**

   **The provided seed file must contain bits that are
     indistinguishable from truly random bits. The seed bits must not
     be reused here or anywhere else.**

   **Failure to provide a proper seed file may result in a
     catastrophic privacy breach.**

   **If you decide to use fixed seed that you re-use for testing
     purposes, then please make sure to implement a mechanism that
     prevents you from accidentally using this in a real
     installation.**

## Usage

Comprehensive documentation ready for printing can be downloaded at
https://www.verificatum.org, but you can also go directly to the
`demo/mixnet` directory and run the `./demo` script if you are
impatient. `demo/mixnet/README.md` explains how to configure the demo.

You can also configure benchmark suites and run them remotely on
multiple machines.

Technical information can, after installing, be found by using

        vtm -h

which gives an overview of the available commands. More usage
information about each command can then be printed similarly.


## API Documentation

You may use

        make api

to invoke Javadoc to build the API. The API is not installed
anywhere. You can copy it to any location.


## Reporting Bugs

Minor bugs should be reported in the repository system as issues or
bugs. Security critical bugs, vulnerabilities, etc should be reported
directly to the Verificatum Project. We will make best effort to
disclose the information in a responsible way before the finder gets
proper credit.

## Sponsoring

Development of additional interface supported by
[VotingWorks](https://www.voting.works) DARPA contract #HR00112290093.
