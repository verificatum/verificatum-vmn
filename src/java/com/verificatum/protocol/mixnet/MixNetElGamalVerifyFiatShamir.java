
/*
 * Copyright 2008-2018 Douglas Wikstrom
 *
 * This file is part of Verificatum Mix-Net (VMN).
 *
 * VMN is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * VMN is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with VMN. If not, see <http://www.gnu.org/licenses/>.
 */

package com.verificatum.protocol.mixnet;

import java.io.File;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Set;

import com.verificatum.arithm.PGroup;
import com.verificatum.crypto.Hashfunction;
import com.verificatum.crypto.HashfunctionHeuristic;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolException;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.info.RootInfo;
import com.verificatum.vcr.VCR;


/**
 * Standalone verifier of a so-called "universally verifiable"
 * heuristically sound proof of correctness of an execution of {@link
 * MixNetElGamal}, i.e., an honest-verifier zero-knowledge proof of
 * knowledge turned non-interactive using the Fiat-Shamir heuristic.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalVerifyFiatShamir {

    /**
     * Stream to which info and errors are written.
     */
    public PrintStream ps;

    /**
     * Amount of information printed during verification.
     */
    public boolean verbose;

    /**
     * Names of test vectors to print.
     */
    public Set<String> testVectorNames;

    /**
     * Decides if stack traces are printed or not.
     */
    public boolean stackTrace;

    /**
     * Session identifier of mix-net.
     */
    String sid;

    /**
     * Certainty with which parameters tested probabilistically are
     * correct.
     */
    int certainty;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Number of bits in the challenge.
     */
    int vbitlenro;

    /**
     * Number of bits used during batching.
     */
    int ebitlenro;

    /**
     * Number of parties executing the protocol.
     */
    int k;

    /**
     * Number of parties needed to violate privacy.
     */
    int threshold;

    /**
     * Description of group in which the protocol was executed.
     */
    String pGroupString;

    /**
     * Group in which the protocol was executed.
     */
    PGroup pGroup;

    /**
     * Group in which plaintexts live when the width is one.
     */
    PGroup plainPGroup;

    /**
     * Description of PRG used to derive random vectors during batching.
     */
    String prgString;

    /**
     * PRG used to derive random vectors during batching.
     */
    PRG prg;

    /**
     * Description of hash function used to implement random oracles.
     */
    String roHashfunctionString;

    /**
     * Hash function used to implement random oracles.
     */
    Hashfunction roHashfunction;

    /**
     * Width of El Gamal keys.
     */
    int keyWidth;

    /**
     * Default width of processed ciphertexts.
     */
    int defaultWidth;

    /**
     * Initializes the hash function defined in the protocol info.
     *
     * @param protocolInfo Protocol info.
     * @param randomSource Source of randomness.
     * @throws ProtocolException If the description of the hash
     * function is invalid.
     */
    private void setHashfunction(final ProtocolInfo protocolInfo,
                                 final RandomSource randomSource)
        throws ProtocolException {

        roHashfunctionString = null;
        try {

            roHashfunctionString =
                protocolInfo.getStringValue(ProtocolElGamal.ROHASH);
            if ("SHA-256".equals(roHashfunctionString)) {
                roHashfunction = new HashfunctionHeuristic("SHA-256");
            } else if ("SHA-384".equals(roHashfunctionString)) {
                roHashfunction = new HashfunctionHeuristic("SHA-384");
            } else if ("SHA-512".equals(roHashfunctionString)) {
                roHashfunction = new HashfunctionHeuristic("SHA-512");
            } else {
                roHashfunction =
                    Marshalizer.
                    unmarshalHexAux_Hashfunction(roHashfunctionString,
                                                 randomSource,
                                                 certainty);
            }
        } catch (final EIOException eioe) {
            throw new ProtocolException("Unable to read hash function "
                                        + "description used to implement "
                                        + "random oracles!", eioe);
        }
    }

    /**
     * Initializes the basic group of prime order used for encryption.
     *
     * @param protocolInfo Protocol info.
     * @param randomSource Source of randomness.
     * @throws ProtocolException If the description of the group is
     * invalid.
     */
    private void setPGroup(final ProtocolInfo protocolInfo,
                           final RandomSource randomSource)
        throws ProtocolException {

        pGroupString = null;
        try {
            pGroupString = protocolInfo.getStringValue(ProtocolElGamal.PGROUP);
            pGroup = Marshalizer.unmarshalHexAux_PGroup(pGroupString,
                                                        randomSource,
                                                        certainty);
        } catch (final EIOException eioe) {
            throw new ProtocolException("Unable to read group description "
                                        + "from protocol info file!", eioe);
        }
    }

    /**
     * Initializes the pseudo-random generator.
     *
     * @param protocolInfo Protocol info.
     * @param randomSource Source of randomness.
     * @throws ProtocolException If the description of the
     * pseudo-random generator is invalid.
     */
    private void setPRG(final ProtocolInfo protocolInfo,
                        final RandomSource randomSource)
        throws ProtocolException {

        prgString = null;
        try {
            prgString = protocolInfo.getStringValue(ProtocolElGamal.PRG);
            if ("SHA-256".equals(prgString)) {
                prg = new PRGHeuristic(new HashfunctionHeuristic("SHA-256"));
            } else if ("SHA-384".equals(prgString)) {
                prg = new PRGHeuristic(new HashfunctionHeuristic("SHA-384"));
            } else if ("SHA-512".equals(prgString)) {
                prg = new PRGHeuristic(new HashfunctionHeuristic("SHA-512"));
            } else {
                prg = Marshalizer.unmarshalHexAux_PRG(prgString,
                                                      randomSource,
                                                      certainty);
            }
        } catch (final EIOException eioe) {
            throw new ProtocolException("Unable to read PRG description "
                                        + "from protocol info file!", eioe);
        }
    }

    /**
     * Creates a verifier.
     *
     * @param protocolInfo Protocol info instance.
     * @param randomSource Source of randomness.
     * @param ps Destination of written information.
     * @param verbose Indicates that information should be output.
     * @param testVectorNames Names of test vectors to print.
     * @param stackTrace Indicates that a stacktrace should be written
     * if there is an error.
     *
     * @throws ProtocolException If the verifier can not be
     * instantiated with the basic parameters by reading from the
     * input.
     */
    public MixNetElGamalVerifyFiatShamir(final ProtocolInfo protocolInfo,
                                         final RandomSource randomSource,
                                         final PrintStream ps,
                                         final boolean verbose,
                                         final Set<String> testVectorNames,
                                         final boolean stackTrace)
        throws ProtocolException {

        String e;

        // Check the package version.
        final String packageVersion =
            protocolInfo.getStringValue(RootInfo.VERSION);
        if (!VCR.version().equals(packageVersion)) {
            e = "Expected package version " + VCR.version()
                + " but the protocol info file was created by a package "
                + "with version " + packageVersion + "!";
            throw new ProtocolError(e);
        }

        this.ps = ps;
        this.verbose = verbose;
        this.testVectorNames = testVectorNames;
        this.stackTrace = stackTrace;

        // Session identifier of mix-net, i.e., the key generation.
        sid = protocolInfo.getStringValue(Protocol.SID);

        certainty = 100; // This is safe to hardcode in this way

        // Auxiliary security parameters.
        vbitlenro = protocolInfo.getIntValue(ProtocolElGamal.VBITLENRO);
        ebitlenro = protocolInfo.getIntValue(ProtocolElGamal.EBITLENRO);
        rbitlen = protocolInfo.getIntValue(Protocol.STATDIST);

        // Number of parties.
        k = protocolInfo.getNumberOfParties();
        threshold = protocolInfo.getIntValue(ProtocolBBT.THRESHOLD);

        // Extract group over which to execute the protocol.
        setPGroup(protocolInfo, randomSource);

        // El Gamal keys may live in a product group.
        keyWidth = protocolInfo.getIntValue(ProtocolElGamal.KEYWIDTH);
        plainPGroup = ProtocolElGamal.getPlainPGroup(pGroup, keyWidth);

        // Extract PRG used to derive random vectors.
        setPRG(protocolInfo, randomSource);

        // Hash function used to implement random oracles.
        setHashfunction(protocolInfo, randomSource);

        defaultWidth = protocolInfo.getIntValue(MixNetElGamal.WIDTH);
    }

    /**
     * Prints a header to indicate that test vectors about a given
     * party is printed.
     *
     * @param l Index of party.
     */
    public void printTestShuffleBegin(final int l) {
        System.out.println("\n###################### BEGIN PARTY "
                           + l + " ######################");
    }

    /**
     * Prints a header to indicate that test vectors about a given
     * party is printed.
     *
     * @param testVectorName Name of test vector.
     * @param l Index of party.
     */
    public void checkPrintTestShuffleBegin(final String testVectorName,
                                           final int l) {
        if (checkTestVector(testVectorName)) {
            printTestShuffleBegin(l);
        }
    }

    /**
     * Prints a header to indicate that test vectors about a given
     * party is printed.
     *
     * @param l Index of party.
     */
    public void printTestShuffleEnd(final int l) {
        System.out.println("\n####################### END PARTY "
                           + l + " #######################");
    }

    /**
     * Prints a test vector.
     *
     * @param testVectorName Name of test vector.
     * @param testVectorString Description of test vector.
     */
    public void printTestVector(final String testVectorName,
                                final String testVectorString) {
        printTestVector(testVectorName, -1, testVectorString);
    }

    /**
     * Prints a test vector.
     *
     * @param testVectorName Name of test vector.
     * @param index Index of party.
     * @param testVectorString Description of test vector.
     */
    public void printTestVector(final String testVectorName,
                                final int index,
                                final String testVectorString) {
        final String s = MixNetElGamalVerifyFiatShamirTool.
            testVectorHeader(0, testVectorName, index);
        System.out.println("\nTEST VECTOR\n" + s + "\n" + testVectorString);
    }

    /**
     * Checks a candidate test vector name.
     *
     * @param testVectorName Name of test vector.
     * @return True or false depending on if a test vector is
     * activated or not.
     */
    public boolean checkTestVector(final String testVectorName) {

        if (testVectorNames.contains(testVectorName)) {
            return true;
        } else {

            final int i = testVectorName.indexOf(".");
            if (i >= 0) {
                return testVectorNames.contains(testVectorName.substring(0, i));
            }
        }
        return false;
    }

    /**
     * Checks a candidate test vector name and prints the
     * corresponding test vector if appropriate.
     *
     * @param testVectorName Name of test vector.
     * @param testVectorString Description of test vector.
     */
    public void checkPrintTestVector(final String testVectorName,
                                     final String testVectorString) {
        if (checkTestVector(testVectorName)) {
            printTestVector(testVectorName, testVectorString);
        }
    }

    /**
     * Checks a candidate test vector name and prints the
     * corresponding test vector if appropriate.
     *
     * @param testVectorName Name of test vector.
     * @param l Index of tester.
     * @param testVector Test vector.
     */
    public void checkPrintTestVector(final String testVectorName,
                                     final int l,
                                     final Object testVector) {
        if (checkTestVector(testVectorName)) {
            final String testVectorString = testVector.toString();
            printTestVector(testVectorName, l, testVectorString);
        }
    }

    /**
     * Checks a candidate test vector name and prints the
     * corresponding test vector if appropriate.
     *
     * @param testVectorName Name of test vector.
     * @param testVector Test vector.
     */
    public void checkPrintTestVector(final String testVectorName,
                                     final Object testVector) {
        if (checkTestVector(testVectorName)) {
            final String testVectorString = testVector.toString();
            printTestVector(testVectorName, testVectorString);
        }
    }

    /**
     * Checks a candidate test vector name and prints the
     * corresponding test vector if appropriate.
     *
     * @param testVectorName Name of test vector.
     * @param l Index of tester.
     * @param testVectorString Description of test vector.
     */
    public void checkPrintTestVector(final String testVectorName,
                                     final int l,
                                     final String testVectorString) {
        if (checkTestVector(testVectorName)) {
            printTestVector(testVectorName, l, testVectorString);
        }
    }

    /**
     * Checks a candidate test vector name and prints the
     * corresponding test vector if appropriate.
     *
     * @param testVectorName Name of test vector.
     * @param testVectorInt Description of test vector.
     */
    public void checkPrintTestVector(final String testVectorName,
                                     final int testVectorInt) {
        if (checkTestVector(testVectorName)) {
            printTestVector(testVectorName, Integer.toString(testVectorInt));
        }
    }

    /**
     * Print header.
     *
     * @param message Message to print.
     */
    void printHeader(final String message) {
        String spacedMessage = "";
        if (!"".equals(message)) {
            spacedMessage = " " + message + " ";
        }
        if (verbose) {
            println("");
            final StringBuilder sb = new StringBuilder();
            sb.append("============");
            sb.append(spacedMessage);
            final int a = Math.max(0, 64 - sb.length());
            for (int i = 0; i < a; i++) {
                sb.append('=');
            }
            println(sb.toString());
        }
    }

    /**
     * Print message.
     *
     * @param message Message to print.
     */
    void print(final String message) {
        if (verbose) {
            final SimpleDateFormat sdf =
                new SimpleDateFormat("yyMMdd HH:mm:ss", Locale.US);
            ps.print(sdf.format(new Date()) + " " + message);
            ps.flush();
        }
    }

    /**
     * Print message and a newline.
     *
     * @param message Message to print.
     */
    void println(final String message) {
        if (verbose) {
            ps.println(message);
        }
    }

    /**
     * Print failure information, inclusing the stacktrace of the
     * given throwable, and then halt.
     *
     * @param message Message to print.
     * @param throwable Throwable causing the failure.
     */
    void failStop(final String message, final Throwable throwable) {
        if (verbose) {

            println("");
            println("");
            println("###############################################");
            println("################## FAIL! ######################");
            println("###############################################");
            println(message);
            println("###############################################");
            println("");

            if (throwable != null && stackTrace) {
                throwable.printStackTrace(ps);
            }

        }
        throw new ProtocolError(message, throwable);
    }

    /**
     * Print failure information and then halt.
     *
     * @param message Message to print.
     */
    void failStop(final String message) {
        failStop(message, null);
    }

    /**
     * Print message and a newline informatively after a failure.
     *
     * @param message Message to print.
     */
    void failInfo(final String message) {
        if (verbose) {
            println("--> " + message);
        }
    }

    /**
     * Returns a verifier for a session stored at the given location.
     *
     * @param nizkp Directory containing non-interactive
     * zero-knowledge proofs.
     * @return Session.
     */
    MixNetElGamalVerifyFiatShamirSession getSession(final File nizkp) {
        return new MixNetElGamalVerifyFiatShamirSession(this, nizkp);
    }
}
