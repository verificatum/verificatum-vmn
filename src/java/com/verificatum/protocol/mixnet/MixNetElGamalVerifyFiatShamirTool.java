
/* Copyright 2008-2019 Douglas Wikstrom
 *
 * This file is part of Verificatum Mix-Net (VMN).
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.verificatum.protocol.mixnet;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.crypto.Hashfunction;
import com.verificatum.crypto.HashfunctionHeuristic;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Marshalizer;
import com.verificatum.eio.TempFile;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolException;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory;
import com.verificatum.protocol.hvzk.ChallengerRO;
import com.verificatum.ui.Util;
import com.verificatum.ui.gen.GenException;
import com.verificatum.ui.gen.GenUtil;
import com.verificatum.ui.gen.GeneratorTool;
import com.verificatum.ui.info.InfoGenerator;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.ui.opt.OptUtil;
import com.verificatum.util.SimpleTimer;


/**
 * Command-line interface to standalone verifier implemented in {@link
 * MixNetElGamalVerifyFiatShamir} of a so called "universally
 * verifiable" heuristically sound proof of correctness of an
 * execution of {@link MixNetElGamal}.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalVerifyFiatShamirTool {

    /**
     * Names of test vectors to print.
     */
    static final ConcurrentMap<String, String> VALID_TEST_VECTOR_NAMES =
        new ConcurrentHashMap<String, String>();

    static {

        VALID_TEST_VECTOR_NAMES.put("par",
                                    "Parameters.");
        VALID_TEST_VECTOR_NAMES.put("par.version",
                                    "Version.");
        VALID_TEST_VECTOR_NAMES.put("par.sid",
                                    "Session identifier of mix-net.");
        VALID_TEST_VECTOR_NAMES.put("par.k",
                                    "Number of mix-servers.");
        VALID_TEST_VECTOR_NAMES.put("par.lambda",
                                    "Threshold number of parties needed to "
                                    + "decrypt.");
        VALID_TEST_VECTOR_NAMES.put("par.n_e",
                                    "Bit length of components in random "
                                    + "vectors used for batching.");
        VALID_TEST_VECTOR_NAMES.put("par.n_r",
                                    "Bit length of random paddings.");
        VALID_TEST_VECTOR_NAMES.put("par.n_v",
                                    "Bit length of challenges.");
        VALID_TEST_VECTOR_NAMES.put("par.s_PRG",
                                    "Description of PRG used for batching.");
        VALID_TEST_VECTOR_NAMES.put("par.s_Gq",
                                    "Description of underlying group.");
        VALID_TEST_VECTOR_NAMES.put("par.s_H",
                                    "Description of hash function used to "
                                    + "implement random oracles.");
        VALID_TEST_VECTOR_NAMES.put("par.omega",
                                    "Width of ciphertexts.");
        VALID_TEST_VECTOR_NAMES.put("par.N_0",
                                    "Number of ciphertexts for which "
                                    + "precomputation is done.");


        VALID_TEST_VECTOR_NAMES.put("der",
                                    "Derived values.");
        VALID_TEST_VECTOR_NAMES.put("der.rho",
                                    "Derived prefix bytes to all random oracle "
                                    + "queries.");


        VALID_TEST_VECTOR_NAMES.put("bas",
                                    "Basic inputs.");
        VALID_TEST_VECTOR_NAMES.put("bas.pk",
                                    "Joint public key.");
        VALID_TEST_VECTOR_NAMES.put("bas.y_l",
                                    "Public keys of threshold number of "
                                    + "mix-servers.");
        VALID_TEST_VECTOR_NAMES.put("bas.x_l",
                                    "Secret keys of some mix-servers "
                                    + "(null if a key is not present).");
        VALID_TEST_VECTOR_NAMES.put("bas.M_omega",
                                    "Space of plaintexts.");
        VALID_TEST_VECTOR_NAMES.put("bas.R_omega",
                                    "Space of randomness.");
        VALID_TEST_VECTOR_NAMES.put("bas.C_omega",
                                    "Space of ciphertexts.");
        VALID_TEST_VECTOR_NAMES.put("bas.h",
                                    "Independent generators.");
        VALID_TEST_VECTOR_NAMES.put("bas.L_0",
                                    "Original list of ciphertexts.");
        VALID_TEST_VECTOR_NAMES.put("bas.L_l",
                                    "Intermediate list of ciphertexts.");


        VALID_TEST_VECTOR_NAMES.put("u",
                                    "Permutation commitment.");


        VALID_TEST_VECTOR_NAMES.put("PoSC",
                                    "Proof of shuffle of commitments.");
        VALID_TEST_VECTOR_NAMES.put("PoSC.s",
                                    "PoSC. Seed to derive batching vector "
                                    + "in hexadecimal notation.");
        VALID_TEST_VECTOR_NAMES.put("PoSC.v",
                                    "PoSC. Integer challenge in hexadecimal "
                                    + "notation.");


        VALID_TEST_VECTOR_NAMES.put("CCPoS",
                                    "Commitment-consistent proof of a "
                                    + "shuffle.");
        VALID_TEST_VECTOR_NAMES.put("CCPoS.s",
                                    "CCPoS. Seed to derive batching "
                                    + "vector in hexadecimal notation.");
        VALID_TEST_VECTOR_NAMES.put("CCPoS.v",
                                    "CCPoS. Integer challenge in hexadecimal "
                                    + "notation.");


        VALID_TEST_VECTOR_NAMES.put("PoS",
                                    "All test vectors for proofs of "
                                    + "shuffles.");
        VALID_TEST_VECTOR_NAMES.put("PoS.s",
                                    "PoS. Seed to derive batching vector "
                                    + "in hexadecimal notation.");
        VALID_TEST_VECTOR_NAMES.put("PoS.v",
                                    "PoS. Integer challenge in hexadecimal "
                                    + "notation.");
        VALID_TEST_VECTOR_NAMES.put("PoS.A",
                                    "PoS. Batched permutation commitment.");
        VALID_TEST_VECTOR_NAMES.put("PoS.F",
                                    "PoS. Batched input ciphertexts.");
        VALID_TEST_VECTOR_NAMES.put("PoS.B",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.C",
                                    "PoS. Derived intermediate values.");
        VALID_TEST_VECTOR_NAMES.put("PoS.D",
                                    "PoS. Derived intermediate values.");
        VALID_TEST_VECTOR_NAMES.put("PoS.Ap",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.Bp",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.Cp",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.Dp",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.Fp",
                                    "PoS. Commitment components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_A",
                                    "PoS. Reply components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_B",
                                    "PoS. Reply components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_C",
                                    "PoS. Reply components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_D",
                                    "PoS. Reply components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_E",
                                    "PoS. Reply components.");
        VALID_TEST_VECTOR_NAMES.put("PoS.k_F",
                                    "PoS. Reply components.");


        VALID_TEST_VECTOR_NAMES.put("Dec",
                                    "Proof of correct decryption.");
        VALID_TEST_VECTOR_NAMES.put("Dec.s",
                                    "Dec. Seed to derive batching vector "
                                    + "in hexadecimal notation.");
        VALID_TEST_VECTOR_NAMES.put("Dec.v",
                                    "Dec. Integer challenge in hexadecimal "
                                    + "notation.");
    }

    /**
     * Factory for creating interface.
     */
    static final ProtocolElGamalInterfaceFactory FACTORY =
        new MixNetElGamalInterfaceFactory();

    /**
     * Session identifier of mix-net.
     */
    String sid;

    /**
     * Certainty with which a modulus is deemed prime.
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
     * Number of parties needed to violate privacy.
     */
    int threshold;

    /**
     * Description of group in which the protocol was executed.
     */
    String pGroupString;

    /**
     * Description of PRG used to derive random vectors during batching.
     */
    String prgString;

    /**
     * Description of hash function used to implement random oracles.
     */
    String roHashfunctionString;

    /**
     * Hash function used to implement random oracles.
     */
    Hashfunction roHashfunction;

    /**
     * Returns a header describing the named test vector.
     *
     * @param columnSize Characters in column storing names.
     * @param testVectorName Name of test vector.
     * @param index Index of this object.
     * @return Header describing the test vector.
     */
    public static String testVectorHeader(final int columnSize,
                                          final String testVectorName,
                                          final int index) {
        String tvn = testVectorName;

        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < columnSize - tvn.length(); i++) {
            sb.append(' ');
        }

        final String key = tvn;
        if (index >= 0) {
            tvn = tvn.substring(0, tvn.length() - 1) + index;
        }

        return sb.toString()
            + String.format("%s - %s", tvn, VALID_TEST_VECTOR_NAMES.get(key));
    }

    /**
     * Returns a header describing the named test vector.
     *
     * @param columnSize Characters in column storing names.
     * @param testVectorName Name of test vector.
     * @return Header describing the test vector.
     */
    public static String testVectorHeader(final int columnSize,
                                          final String testVectorName) {
        return testVectorHeader(columnSize, testVectorName, -1);
    }

    /**
     * Creates a verifier tool.
     *
     * @param protInfo Protocol info representing the mix-net.
     * @param randomSource Source of randomness.
     *
     * @throws ProtocolException If this tool can not be instantiated
     * based on the protocol info.
     */
    public MixNetElGamalVerifyFiatShamirTool(final ProtocolInfo protInfo,
                                             final RandomSource randomSource)
        throws ProtocolException {

        // Session identifier of mix-net, i.e., the key generation.
        sid = protInfo.getStringValue(Protocol.SID);

        // Auxiliary security parameters.
        certainty = 100;
        vbitlenro = protInfo.getIntValue(ProtocolElGamal.VBITLENRO);
        ebitlenro = protInfo.getIntValue(ProtocolElGamal.EBITLENRO);

        rbitlen = protInfo.getIntValue(Protocol.STATDIST);

        // Number of parties.
        threshold = protInfo.getIntValue(ProtocolBBT.THRESHOLD);

        // Extract description of group over which to execute the
        // protocol.
        pGroupString = protInfo.getStringValue(ProtocolElGamal.PGROUP);

        // Extract description of PRG used to derive random vectors.
        prgString = protInfo.getStringValue(ProtocolElGamal.PRG);

        // Hash function used to implement random oracles.
        roHashfunctionString = null;
        try {

            roHashfunctionString =
                protInfo.getStringValue(ProtocolElGamal.ROHASH);
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
     * Instantiate challenger.
     *
     * @param auxsid Auxiliary session identifier.
     * @return Challenger.
     */
    protected ChallengerRO getChallenger(final String auxsid) {

        final String rosid = sid + "." + auxsid;

        final ByteTree bt =
            new ByteTree(new ByteTree(ExtIO.getBytes(rosid)),
                         ByteTree.intToByteTree(rbitlen),
                         ByteTree.intToByteTree(vbitlenro),
                         ByteTree.intToByteTree(ebitlenro),
                         new ByteTree(ExtIO.getBytes(prgString)),
                         new ByteTree(ExtIO.getBytes(pGroupString)),
                         new ByteTree(ExtIO.getBytes(roHashfunctionString)));

        return new ChallengerRO(roHashfunction,
                                roHashfunction.hash(bt.toByteArray()));
    }

    /**
     * Compute product of decryption factors.
     *
     * @param decryptionFactors Decryption factors to multiply.
     * @return Product of decryption factors.
     */
    protected PGroupElementArray
        mulDecryptionFactors(final PGroupElementArray[] decryptionFactors) {

        PGroupElementArray decryptionFactorsProd = decryptionFactors[1];
        for (int l = 2; l <= threshold; l++) {
            decryptionFactorsProd =
                decryptionFactorsProd.mul(decryptionFactors[l]);
        }
        return decryptionFactorsProd;
    }

    /**
     * Returns true or false depending on if the given flag appears in
     * the comma separated list of taboo flags.
     *
     * @param tabooFlags Taboo flags.
     * @param flag Flag to look for.
     * @return True or false depending on if the given flag appears in
     * the comma separated list of taboo flags.
     */
    static boolean keep(final StringBuilder tabooFlags, final String flag) {
        final String normTabooFlags = tabooFlags + ",";
        return normTabooFlags.indexOf(flag + ",") == -1;
    }

    /**
     * Returns a comma-separated list of the input flags that do not
     * appear in the comma-separated list of tabu flags.
     *
     * @param flags Flags to be tested.
     * @param tabooFlags Comma-separated list of flags to remove.
     * @return Comma-separated list of input flags that do not appear
     * in the list of tabu flags.
     */
    static String keepFlags(final String flags,
                            final StringBuilder tabooFlags) {

        final String[] flagsArray = flags.split(",");
        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < flagsArray.length; i++) {

            final String flag = flagsArray[i];

            if (!"".equals(flag) && keep(tabooFlags, flag)) {
                sb.append(',').append(flag);
            }
        }
        if (sb.length() > 0) {
            sb.deleteCharAt(0);
        }
        return sb.toString();
    }

    /**
     * Adds an option if it is not one of the taboo flags.
     *
     * @param tabooFlags String of taboo flags.
     * @param opt Parsed options.
     * @param flag Flag under which to add an option.
     * @param valueString Value associated with flag.
     * @param description Description of flag.
     */
    static void addOption(final StringBuilder tabooFlags, final Opt opt,
                          final String flag, final String valueString,
                          final String description) {
        if (keep(tabooFlags, flag)) {
            opt.addOption(flag, valueString, description);
        }
    }

    /**
     * Generates option instance.
     *
     * @param commandName Command name used when printing usage
     * info.
     * @param tabooFlags Commma-separated list of options to remove.
     * @return Option instance.
     */
    @SuppressWarnings("PMD.CyclomaticComplexity")
    static Opt opt(final String commandName, final String tabooFlags) {

        // Implementation specifict options.
        final String idf = "-wd,-a,-e,-t,-v";

        // Options for individual usage forms.
        final String mixFlags = "-noposc,-noccpos,-nopos,-nodec,-width," + idf;
        final String shuffleFlags = "-noposc,-noccpos,-width," + idf;
        final String decryptFlags = "-width," + idf;
        final String sloppyFlags = idf;

        // Things that should always be removed before printing
        // compatibility usage information.
        final String df = idf + ",-sloppy,-h";

        // Check if -mc flag was used.
        final StringBuilder tf = new StringBuilder();
        if (tabooFlags != null) {
            if ("".equals(tabooFlags)) {
                tf.append(df);
            } else {
                tf.append(tabooFlags).append(',').append(df);
            }
        }

        // Printing help for printing test vectors and printing test
        // vectors stiick together.
        if (!keep(tf, "-t")) {
            tf.append(",-th");
        }
        if (!keep(tf, "-th")) {
            tf.append(",-t");
        }

        final String defaultErrorString =
            "Invalid invocation. Please use \"" + commandName
            + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);


        // We only show the possibility of using taboo flags if the -c
        // option was not used.
        if (tf.length() == 0) {

            // Sorted union of options.
            final String usageFlags = "-nopre -mix -shuffle -decrypt -width";
            final String functionalFlags = "-nopos -nodec -noposc -noccpos";

            opt.addOption("-mc", "",
                          "Print modified compatibility usage information. "
                          + "This can be used by others to print the usage "
                          + "information that their own verifiers must "
                          + "provide. Partial implementations can remove "
                          + "certain functionality using flags.");
            opt.addParameter("command",
                             "Command name of independent verifier. The name "
                             + "may not contain any \"-\" characters.");
            opt.addParameter("flags",
                             "A comma-separated list of option flags to be "
                             + "removed from the compatibility usage "
                             + "information. The following flags are "
                             + "available: \n"
                             + usageFlags + "\n"
                             + functionalFlags);
        }

        opt.addOption("-h", "", "Print usage information.");
        opt.addOption("-c", "", "Print compatibility usage information.");
        opt.addOption("-version", "", "Print the package version.");

        if (keep(tf, "-mix") || keep(tf, "-shuffle") || keep(tf, "-decrypt")) {
            opt.addParameter("protInfo", "Protocol info file.");
            opt.addParameter("nizkp",
                             "Directory containing the non-interactive "
                             + "zero-knowledge proof of correctness using "
                             + "the Fiat-Shamir heuristic.");
            opt.addOption("-auxsid", "value",
                          "Verify that the given auxiliary session identifier "
                          + "matches that in the proof. This is required when "
                          + "the auxiliary session identifier in the proof is "
                          + "not \"default\".");
        }

        addOption(tf, opt, "-v", "", "Verbose output, i.e., turn on output.");

        addOption(tf, opt, "-mix", "", "Check proof of mixing.");

        addOption(tf, opt, "-shuffle", "", "Check proof of shuffle.");

        addOption(tf, opt, "-decrypt", "", "Check proof of decryption.");

        addOption(tf, opt, "-sloppy", "",
                  "Check proof of mixing/shuffle/decryption depending "
                  + "on what is specified in the proof itself using "
                  + "the auxiliary session identifier and width "
                  + "specified in the proof itself. WARNING! If these "
                  + "values are not verified using other means, then "
                  + "this does not constitute a complete verification.");

        if (keep(tf, "-mix") || keep(tf, "-shuffle") || keep(tf, "-decrypt")) {
            addOption(tf, opt, "-width", "value",
                      "Verify that the given width matches that in the "
                      + "proof. This is required when the width in the "
                      + "proof is different from the width in the "
                      + "protocol info file.");
        }

        if (keep(tf, "-mix")) {
            addOption(tf, opt, "-nopos", "",
                      "Turn off verification of proofs of shuffles. If "
                      + "pre-computation is used, this turns off "
                      + "verification of both proofs of shuffles of "
                      + "commitments and commitment-consistent proofs "
                      + "of shuffles.");

            addOption(tf, opt, "-nodec", "",
                      "Turn off verification of proof of decryption.");
        }

        if (keep(tf, "-mix") || keep(tf, "-shuffle")) {
            addOption(tf, opt, "-noposc", "",
                      "Turn off verification of proofs of shuffles of "
                      + "commitments. This is only possible if "
                      + "pre-computation was used during execution.");

            addOption(tf, opt, "-noccpos", "",
                      "Turn off verification of commitment-consistent "
                      + "proofs of shuffles. This is only possible if "
                      + "pre-computation was used during execution.");
        }

        addOption(tf, opt, "-wd", "dir",
                  "Directory for temporary files (default is "
                  + "a unique subdirectory of /tmp/com.verificatum). "
                  + "This directory is deleted on exit.");

        addOption(tf, opt, "-a", "value",
                  "Determines if file based arrays are used or not. "
                  + "Legal values are \"file\" or \"ram\" and the "
                  + "default is \"file\".");

        addOption(tf, opt, "-e", "",
                  "Show stack trace of an exception.");

        addOption(tf, opt, "-t", "names",
                  "Print the given comma-separated test vectors. The "
                  + "\"-th\" option can be used to list the available "
                  + "test vectors.");

        addOption(tf, opt, "-th", "",
                  "List the available test vectors. The names are "
                  + "chosen to be easily related to the notation "
                  + "used in the document that describes the "
                  + "non-interactive zero-knowledge proof of "
                  + "correctness. In particular for programmers "
                  + "that are familiar with LaTeX.");

        int usageIndex = 0;

        opt.addUsageForm();
        opt.appendToUsageForm(usageIndex, "-h###");
        usageIndex++;

        opt.addUsageForm();
        opt.appendToUsageForm(usageIndex, "-c###");
        usageIndex++;

        if (keep(tf, "-th")) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex, "-th###");
            usageIndex++;
        }

        final String pnString = "#protInfo,nizkp#";

        if (keep(tf, "-mix")) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex,
                                  "-mix#-auxsid,"
                                  + keepFlags(mixFlags, tf)
                                  + pnString);
            usageIndex++;
        }

        if (keep(tf, "-shuffle")) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex,
                                  "-shuffle#-auxsid,"
                                  + keepFlags(shuffleFlags, tf)
                                  + pnString);
            usageIndex++;
        }

        if (keep(tf, "-decrypt")) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex,
                                  "-decrypt#-auxsid,"
                                  + keepFlags(decryptFlags, tf)
                                  + pnString);
            usageIndex++;
        }

        if (keep(tf, "-sloppy")) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex,
                                  "-sloppy#"
                                  + keepFlags(sloppyFlags, tf)
                                  + pnString);
            usageIndex++;
        }

        if (tf.length() == 0) {
            opt.addUsageForm();
            opt.appendToUsageForm(usageIndex, "-mc##command#flags");
            usageIndex++;
        }

        opt.addUsageForm();
        opt.appendToUsageForm(usageIndex, "-version###");

        final StringBuilder sb = new StringBuilder();
        sb.append(
"Verifies the overall correctness of an execution using the intermediate "
+ "results and the zero-knowledge proofs of correctness using the "
+ "Fiat-Shamir heuristic in the given proof directory. The verification of "
+ "certain parts can be turned off to simplify a limited form of online "
+ "verification and simplify debugging of other verifiers.");

        if (tf.length() == 0) {
            sb.append(
"\n\n"
+ "WARNING!\n"
+ "Using this in a real election gives SOME assurance, but it does "
+ "NOT eliminate the need for an independently implemented verifier "
+ "according to the human-readable description of the universally verifiable "
+ "proof resulting from an execution of the mix-net. This document is "
+ "available at https://www.verificatum.org."
+ "\n\n"
+ "The main motivations of this tool are to:\n"
+ "(a) debug the description of the universally verifiable proof,\n"
+ "(b) benchmark the running time of verifiers,\n"
+ "(c) serve as a reference implementation to implementors of\n"
+ "    their own verifiers, and\n"
+ "(d) check the compatibility of independent verifiers with\n"
+ "    the requirements of the description of the universally\n"
+ "    verifiable proof."
+ "\n\n"
+ "For this purpose it provides a feature-rich way to print test "
+ "vectors of intermediate results and express compatibility.");
        }

        if (!keep(tf, "-nopre")) {
            sb.append("\n\nProofs with pre-computing can not be verified using "
                      + "this verifier.");
        }

        opt.appendDescription(sb.toString());

        return opt;
    }

    /**
     * Instantiates a random source as defined in command-line
     * arguments.
     *
     * @param args Command line arguments.
     * @return Random source defined by the input.
     * @throws ProtocolException If the description of the random
     * source is invalid.
     */
    private static RandomSource getRandomSource(final String[] args)
        throws ProtocolException {
        try {
            final File rsFile = new File(args[1]);
            final File seedFile = new File(args[2]);
            final File tmpSeedFile = new File(args[2] + "_TMP");
            return GeneratorTool.standardRandomSource(rsFile,
                                                      seedFile,
                                                      tmpSeedFile);
        } catch (final GenException ge) {
            throw new ProtocolException(ge.getMessage(), ge);
        }
    }

    /**
     * Parses the contents of the command line.
     *
     * @param args Command line arguments.
     * @return Parsed command line arguments.
     * @throws ProtocolException If parsing fails.
     */
    @SuppressWarnings("PMD.CyclomaticComplexity")
    private static Opt parseCommandLine(final String[] args)
        throws ProtocolException {
        try {
            String commandName = args[0];
            String[] newArgs = Arrays.copyOfRange(args, 3, args.length);

            // We must catch the taboo flags before we create the
            // Opt. This is the best way to do this.

            String icommandName = null;
            String tabooFlags = null;

            final int len = newArgs.length;

            if (0 < len && len < 4) {
                if (len == 1 && newArgs[0].equals("-c")) {

                    tabooFlags = "";
                    newArgs = new String[1];
                    newArgs[0] = "-h";

                } else if (newArgs[0].equals("-mc")) {

                    int i = 1;
                    if (i < len) {
                        icommandName = newArgs[i];
                        if (icommandName.indexOf("-") == -1) {
                            i++;
                            if (i < len) {
                                tabooFlags = newArgs[i];
                            } else {
                                tabooFlags = "";
                            }
                        }
                    }

                    if (tabooFlags != null) {
                        commandName = icommandName;
                        newArgs = new String[1];
                        newArgs[0] = "-h";
                    }
                }
            }

            final Opt opt = opt(commandName, tabooFlags);
            opt.parse(newArgs);
            return opt;

        } catch (final OptException oe) {
            throw new ProtocolException(oe.getMessage(), oe);
        }
    }

    /**
     * Verifies that the exception flag and verbose flags are
     * compatible.
     *
     * @param eFlag Exception flag value.
     * @param verbose Verbose flag value.
     * @throws ProtocolException If flags are incompatible.
     */
    private static void sanityCheckEandV(final boolean eFlag,
                                         final boolean verbose)
    throws ProtocolException {
        if (eFlag && !verbose) {
            final String es = "The option \"-e\" can only be used in "
                + "combination with \"-v\".";
            throw new ProtocolException(es);
        }
    }

    /**
     * Prints all available test vectors.
     */
    private static void printTestVectors() {

        final StringBuilder sb = new StringBuilder();
        final String description =
            "\nPrinting Test Vectors\n\n"
            + "A specific test vector can be selected to be printed "
            + "by using its full name, but it is also possible to "
            + "select a group of related test vectors by using their "
            + "common prefix, e.g., to print all available test "
            + "vectors starting with PoS simply use \"PoS\". Multiple "
            + "test vectors (or groups of test vectors) can be printed "
            + "by separating them with commas.\n\n";

        sb.append(Util.breakLines(description, Opt.LINE_WIDTH));
        sb.append("The following test vectors are available:\n");

        // Build string of all available test vector names.
        final TreeSet<String> keys =
            new TreeSet<String>(VALID_TEST_VECTOR_NAMES.keySet());
        final Iterator<String> it = keys.iterator();

        while (it.hasNext()) {
            sb.append('\n');
            sb.append(testVectorHeader(12, it.next()));
        }
        sb.append('\n');

        System.out.println(sb.toString());
    }

    /**
     * Extracts the test vector names from the command line arguments.
     *
     * @param opt Parsed command line arguments.
     * @return Test vector names extracted from the command line
     * arguments.
     * @throws ProtocolException If the command line arguments contain
     * invalid test vector names.
     */
    private static Set<String> getTestVectorNames(final Opt opt)
        throws ProtocolException {

        final HashSet<String> testVectorNames = new HashSet<String>();

        if (opt.valueIsGiven("-t")) {

            final String[] tp = opt.getStringValue("-t").split(",");

            for (int i = 0; i < tp.length; i++) {

                if (VALID_TEST_VECTOR_NAMES.containsKey(tp[i])) {

                    testVectorNames.add(tp[i]);

                } else {

                    final String e =
                        "Unknown test vector name! (" + tp[i] + ")";
                    throw new ProtocolException(e);
                }
            }
        }

        return testVectorNames;
    }

    /**
     * Sets the storage model used for arrays of some arithmetic
     * objects.
     *
     * @param opt Parsed command line arguments.
     * @throws ProtocolException If setting the storage model fails.
     */
    private static void setArraysStorageModel(final Opt opt)
        throws ProtocolException {
        if (opt.valueIsGiven("-a")) {

            final String arrays = opt.getStringValue("-a");

            if ("ram".equals(arrays)) {

                LargeIntegerArray.useMemoryBased();

            } else if ("file".equals(arrays)) {

                LargeIntegerArray.useFileBased();

            } else {

                throw new ProtocolException("Unknown parameter to \"-a\"!");
            }
        } else {

            LargeIntegerArray.useFileBased();
        }
    }

    /**
     * Check that the suppression flags are consistent.
     *
     * @param session Session to be verified.
     * @param opt Parsed command line arguments.
     * @throws ProtocolException If the suppression flags are
     * inconsistent.
     */
    private static void
        sanityCheckNoFlags(final MixNetElGamalVerifyFiatShamirSession session,
                           final Opt opt)
        throws ProtocolException {

        if (opt.valueIsGiven("-nopos")
            && (opt.valueIsGiven("-noposc")
                || opt.valueIsGiven("-noccpos"))) {
            final String e =
                "The option \"-nopos\" is incompatible with both "
                + "\"-noposc\" and \"-noccpos\"";
            throw new ProtocolException(e);
        }

        if (!session.precomp()
            && (opt.valueIsGiven("-noposc")
                || opt.valueIsGiven("-noccpos"))) {
            final String e =
                "The options \"-noposc\" and \"-noccpos\" can not "
                + "be used for proofs of executions where no "
                + "pre-computation took place!";
            throw new ProtocolException(e);
        }
    }

    /**
     * Extracts session parameters from parsed command line.
     *
     * @param opt Parsed command line arguments.
     * @return Expected session parameters.
     */
    private static SessionParams getSessionParams(final Opt opt) {

        String expectedType;
        String expectedAuxsid;
        int expectedWidth;

        if (opt.getBooleanValue("-sloppy")) {

            // Sloppy means that we extract the type of the proof, the
            // auxiliary session identifier, and the width from the
            // proof itself. This is sloppy, since the proof must be
            // of a given type in a given application and the operator
            // should check this.

            expectedType = null;
            expectedAuxsid = null;
            expectedWidth = -1;

        } else {

            // Determine expected type.
            if (opt.getBooleanValue("-mix")) {
                expectedType = MixNetElGamalSession.MIX_TYPE;
            } else if (opt.getBooleanValue("-shuffle")) {
                expectedType = MixNetElGamalSession.SHUFFLE_TYPE;
            } else { // -decrypt
                expectedType = MixNetElGamalSession.DECRYPT_TYPE;
            }

            // Determine expected auxiliary session identifier.
            if (opt.valueIsGiven("-auxsid")) {
                expectedAuxsid = opt.getStringValue("-auxsid");
            } else {
                expectedAuxsid = "default";
            }

            // Determine expected width.
            if (opt.valueIsGiven("-width")) {
                expectedWidth = opt.getIntValue("-width");
            } else {
                expectedWidth = 0;
            }
        }

        final boolean expectedDec = !opt.getBooleanValue("-nodec");

        final boolean expectedPos = !opt.getBooleanValue("-nopos");
        final boolean expectedPosc =
            expectedPos && !opt.getBooleanValue("-noposc");
        final boolean expectedCcpos =
            expectedPos && !opt.getBooleanValue("-noccpos");

        return new SessionParams(expectedType,
                                 expectedAuxsid,
                                 expectedWidth,
                                 expectedDec,
                                 expectedPosc,
                                 expectedCcpos);
    }

    /**
     * Command line interface.
     *
     * @param args Command line arguments.
     */
    public static void main(final String[] args) {

        final String stitch =
            "----------------------------------------------------------------";

        // Make sure that we are invoked from a wrapper.
        if (args.length < 3) {
            System.err.println("The first three parameters must be "
                               + "<commandname> <random source file> "
                               + "<random seed file>");
            System.exit(1);
        }

        // We must treat the flags -e and -cerr in an ad hoc way to
        // make sure that they work even when parsing the command line
        // fails.
        final boolean cerrFlag = GenUtil.specialFlag("-cerr", args);
        final boolean eFlag = GenUtil.specialFlag("-e", args);

        final SimpleTimer timer = new SimpleTimer();

        try {

            // Initialize random source.
            final RandomSource randomSource = getRandomSource(args);

            // Set up command name and random source.
            final Opt opt = parseCommandLine(args);

            // Determine if we should use verbose output or not.
            final boolean verbose = opt.getBooleanValue("-v");
            sanityCheckEandV(eFlag, verbose);

            // If help or version flags are given we act accordingly.
            OptUtil.processHelpAndVersion(opt);

            if (verbose) {
                System.out.println(stitch);
                System.out.println("Verify Fiat-Shamir proof");
                System.out.println(stitch);
            }

            // Print a list of all available test vectors that can be
            // printed.
            if (opt.getBooleanValue("-th")) {

                printTestVectors();
                return;
            }

            // Determine points where we print test vectors.
            final Set<String> testVectorNames = getTestVectorNames(opt);

            // The default working directory is probably safe, but in
            // any case it can be overridden from a wrapper of this
            // program.
            try {
                TempFile.init(opt.getStringValue("-wd", ""), randomSource);
            } catch (EIOException eioe) {
                throw new ProtocolFormatException(eioe.getMessage(), eioe);
            }

            // Arrays can be stored in memory or on file. The default
            // is on file.
            setArraysStorageModel(opt);

            // Parse protocol info.
            final File protInfoFile =
                new File(opt.getStringValue("protInfo"));
            final InfoGenerator generator =
                FACTORY.getGenerator(protInfoFile);

            final ProtocolInfo protInfo =
                Protocol.getProtocolInfo(generator, protInfoFile);

            // Determine directory containing proofs.
            final File nizkp = new File(opt.getStringValue("nizkp"));

            final MixNetElGamalVerifyFiatShamir verifier =
                new MixNetElGamalVerifyFiatShamir(protInfo,
                                                  randomSource,
                                                  System.out,
                                                  verbose,
                                                  testVectorNames,
                                                  eFlag);

            final MixNetElGamalVerifyFiatShamirSession session =
                verifier.getSession(nizkp);

            // Verify that suppression flags are compatible with the
            // proof and other flags.
            sanityCheckNoFlags(session, opt);

            // Expected parameters of proof.
            session.verify(getSessionParams(opt));

            if (verbose) {

                // Size of proof.
                long nizkpSize;
                try {
                    nizkpSize = ExtIO.fileSize(nizkp);
                } catch (IOException ioe) {
                    final String e = "Unable to determine communicated bytes!";
                    throw new ProtocolError(e, ioe);
                }
                final String hNizkpSize = ExtIO.bytesToHuman(nizkpSize);
                final String nizkpString =
                    String.format("Proof size is %s  (%d bytes).",
                                  hNizkpSize, nizkpSize);

                // Execution time.
                final String timeString =
                    String.format("Completed verification after %s  (%s ms).",
                                  timer, timer.elapsed());

                System.out.println(stitch);
                System.out.println(nizkpString);
                System.out.println(timeString);
                System.out.println();
            }

        // PMD does not understand this.
        } catch (final ProtocolFormatException pfe) { // NOPMD

            GenUtil.processErrors(pfe, cerrFlag, eFlag);

        } catch (final ProtocolException ppe) { // NOPMD

            GenUtil.processErrors(ppe, cerrFlag, eFlag);

        } catch (final ProtocolError pe) { // NOPMD

            GenUtil.processErrors(pe, cerrFlag, eFlag);

        } finally {

            TempFile.free();
        }
    }
}
