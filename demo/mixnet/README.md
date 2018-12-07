# DEMO INSTRUCTIONS

## Introduction

The demo has been used for years, but we have not spent much time on
handling incorrect use gracefully, so please read the instructions
carefully.

Before we describe the demo scripts we point out that the demo scripts
in this directory run the mix-net from the command line *exactly* in
the same way it would be run by an operator; even when a demo is run
remotely. The demo scripts are *portable* and run on a variety of
Unix/Linux This is important to: debug the mix-net exactly as it is
used, provide correct benchmarks, minimize the number of external
dependencies even for testing an installation, and to allow parties to
choose a platform that they are comfortable with.

The drawback of this approach is that we are restricted to the
Bourne/Ash shell (on almost all Un*xes this is /bin/sh) in our scripts
and there is a fair amount of escape quoting and elaborate code that
sends and executes commands, e.g., we use wrappers to provide a
uniform setting for executing commands locally or remotely depending
on how the demo is configured.

An often overlooked advantage with the Bourne shell is that it is a
more conservative choice in terms of security and stability compared
to more expressive and complex shells such as: bash, csh, or tcsh.

## Usage

The first five scripts should be executed in the order they are
presented below. The remaining scripts can be executed in many
different orders. Please note that one demo script must be allowed to
finish, i.e., all windows it opens must close and it must return the
prompt, before another command is executed.

| Script         | Description
|----------------|-------------------------------------------------------------
| `./clean`      | Remove any previous demo directories as well as the log files mentioned below.
| `./info_files` | Generate info files for the mix-servers and merge them, i.e., the information exchange of operators during what would be a set-up phase in a real installation. This demonstrates the use of `vmni -prot ...`, `vmni -party ...`, and `vmni -merge ...`.
| `./keygen`     | Execute the distributed key generation phase. The result is the joint public key of the mix-net. This demonstrates the use of `vmn -keygen ...`.
| `./gen_ciphs`  | Generate demo ciphertexts of the messages `0000000`, `00000001`, `00000002`, etc. May be executed before `./precomp` below. This is only used in the demonstrator, i.e., it does not on its own demonstrate any functionality.
| `./mix`        | Execute the mixing phase. This demonstrates the use of `vmn -mix ...`
| `./shuffle`    | Execute only shuffling without decryption. This demonstrates the use of `vmn -shuffle ...`.
| `./decrypt`    | Execute only the decryption phase without shuffling. This demonstrates the use of `vmn -decrypt ...`.
| `./precomp`    | Execute the pre-computation phase. This demonstrates the use of `vmn -precomp ...`.
| `./delete`     | Delete the most recent session. This demonstrates the use of `vmn -delete`.
| `./lact`       | List the set of active mix-servers. This demonstrates the use of `vmn -lact ...`.
| `./sact`       | Set the list of active mix-servers. This demonstrates the use of, e.g., `vmn -sact '{1,2,3}'`.
| `./verify`     | Execute the reference implementation of the standalone verifier of the non-interactive Fiat-Shamir proofs. This is only possible if the mix-net is executed using such proofs (default). This demonstrates the use of `vmnv ...`.
| `./demo`       | Execute the following commands in order: `./clean; ./info_files; ./keygen; ./precomp; ./mix` (The precomputation phase is avoided by setting `MAX_NO_CIPHERTEXTS` to zero in the `conf` file, which is the case by default.)

The number of mix-servers, ciphertexts, key width, width, group, etc
can be configured by editing the file `conf`. It contains detailed
information about various options and examples. You can always restore
the original conf file using ./restore. Note that this configuration
file is only used for demo purposes is not an example of a
configuration file of an individual mix-server.

The final plaintexts appear in the individual directories of the
mix-servers in the file `plaintexts`. With the default configuration
they end up in, e.g., mydemodir/Party01, either in this directory or
in the home directory of each server if the demo is run remotely.


## Log Files

There are three log files:

1. `vmn_log` is the log file of the first mix-server.

2. `vmnv_log` is the log file of the verifier.

3. `demo_log` is the log file of the demonstrator. This contains the
    main demo parameters.

The log files are reset when the script `./clean` is executed.


## Trouble Shooting

If you interrupt the demonstration, then there may be lingering
processes that prevent the demonstration servers to listen to their
ports. If this happens you must manually kill the lingering processes,
e.g., `killall java` if you are not running other JVMs.

If you are running your demo on the same machine as somebody else, you
may need to manually specify the `HTTPOFFSET` and `HINTOFFSET`
variables in the `conf` file to avoid port conflicts, i.e., they can
not all use the default port numbers for their communication servers.


## Remote Demo

The recommended way to set up a remote demonstration is to:

1. For each machine:

    * Install the software (see the `README.md` in the main
      directory as well as the information at
      https://www.verificatum.org ).

    * Run a local demonstration to make sure that your installation
      works properly.

    * Run a "remote" demonstration, but with all servers running on
      the local machine (effectively using the loop back interface),
      to make sure that it works on a single machine, i.e., uncomment
      the lines starting with `DEFAULT_USERNAME` and `DEFAULT_HOST`
      and edit them appropriately.

    * Make sure that you have set up password-less login with ssh. You
      do not need password-less login between each pair of
      servers. You only need password-less login from the machine from
      which the demonstration is orchestrated to each machine playing
      the role of a mix-server.

    * Make sure that the firewall is open at the ports specified in
      the `conf` file. If a server is run behind a firewall, e.g.,
      using NAT, then make sure that port forwarding is set up
      correctly and that you use the correct local hostname/IP
      address.

2. Test to login to each remote machine from the machine where you
   orchestrate, to make sure that your password-less ssh login works.

3. Run the remote demonstration with small key sizes and a small
   number of ciphertexts to see that the setup works. Then try larger
   parameters.

4. Note that if you run a remote demonstration, then `clean` will
   delete files *remotely* as well. It is wise to clean the
   demonstration directories *before* editing the `conf` file. If you
   modify the `conf` file before you run `clean`, then the remote
   clean will fail, and possibly hang.


## Benchmarks

When you are confortable with running remote demos, then you may run
benchmarks. Each benchmark simply executes a demo with a given
configuration, extracts the relevant data, and interpolates the data
to derive formulas.

The configuration for the demo is found in `benchmarks/bench_config`
and the benchmark suite is run by executing

        ./bench

We suggest to run the benchmark with small parameters first. In
particular `BENCH_BENCHMARKSIZE` should be left as 1 to verify that
your setup is correct. You can also modify `benchmarks/bench_config`
to only run a subset of the benchmarks.

Please be **patient**, the benchmark necessarily takes a considerable
amount of time.

Keep in mind that some cheap DNS services are not robust in the sense
that they may delay requests when queried frequently from the same
origin, so when you run a benchmark with large parameters, we suggest
that you use the IP addresses directly in `bench_config`.

If you want to provide your own benchmark, then we suggest that you
use one of the existing benchmarks as a template. We welcome
additions, so please send it to us!

At the end of the execution of the benchmarks, `benchresults/`
contains a subdirectory for each benchmark. Each such subdirectory
contains:

1. `demo_log` which is the log file of the benchmark. This describes
   the main parameters of benchmark, which commands are executed, and
   a summary of the results.

2. `vmn_log` which is the log file of the first mix-server. This
    contains the log of all ways the mix-net is used during the
    benchmark.

and if non-interactive zero-knowledge proofs were used also:

3. `vmnv_log` which is the log file of the verifier. This contains the
    logs of all verifications performed during the benchmark.
