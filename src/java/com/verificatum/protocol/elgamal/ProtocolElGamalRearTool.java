
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

package com.verificatum.protocol.elgamal;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PGroupUtil;
import com.verificatum.arithm.PPGroup;
import com.verificatum.crypto.RandomSource;
import com.verificatum.crypto.CryptoException;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.TempFile;
import com.verificatum.protocol.ProtocolDefaults;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.ui.gen.GenUtil;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.ui.opt.OptUtil;

/**
 * Command-line tool used to choose subsets of the group elements of
 * public keys, lists of ciphertxts, and lists of plaintexts.
 *
 * @author Douglas Wikstrom
 */
public final class ProtocolElGamalRearTool {

    /**
     * Raw interface for reading and writing arithmetic objects
     * from/to file.
     */
    private static final ProtocolElGamalInterfaceRaw RAW =
        new ProtocolElGamalInterfaceRaw();

    /**
     * Parser of command-line arguments.
     */
    private static final ProtocolElGamalRearParser PARSER =
        new ProtocolElGamalRearParser();

    /**
     * Avoid accidental instantiation.
     */
    private ProtocolElGamalRearTool() { }

    /**
     * Re-arranges the public keys.
     *
     * @param inputPkeys Public keys to be rearranged.
     * @param format Description of which parts of the input public
     * keys are used to form the output public keys.
     * @return Rearranged public keys.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static List<PGroupElement>
        rearrangePkeys(final List<PGroupElement> inputPkeys,
                       final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        // Splice the public keys into the first and second
        // components.
        List<PGroupElement> uparts = null;
        List<PGroupElement> vparts = null;
        try {
            uparts = PGroupUtil.unsafeProject(inputPkeys, 0);
            vparts = PGroupUtil.unsafeProject(inputPkeys, 1);
        } catch (ArithmFormatException afe) {
            final String e = "Failed to project to part of public key!";
            throw new ProtocolFormatException(e, afe);
        }

        final PGroup atomicPGroup =
            uparts.get(0).getPGroup().getPrimeOrderPGroup();

        // Re-arrange each of the two components separately.
        final List<List<PGroupElement>> components =
            new ArrayList<List<PGroupElement>>();
        components.add(ProtocolElGamalRear.rearrangeElements(atomicPGroup,
                                                             uparts,
                                                             format));
        components.add(ProtocolElGamalRear.rearrangeElements(atomicPGroup,
                                                             vparts,
                                                             format));

        // Combine the components to ciphertexts and write the results
        // to the output files.
        try {
            return PGroupUtil.product(components);
        } catch (ArithmFormatException afe) {
            throw new ProtocolFormatException("Failed to take product!", afe);
        }
    }

    /**
     * Re-arranges the public keys.
     *
     * @param filenames Names of both input files and output files.
     * @param numberOfInputs Number of inputs.
     * @param format Description of which parts of the input public
     * keys are used to form the output public keys.
     * @param randomSource Source of randomness.
     * @param certainty Determines the probability that an invalid
     * public key is deemed valid.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void
        rearrangePkeys(final String[] filenames,
                       final int numberOfInputs,
                       final List<List<ProtocolElGamalRearPosition>> format,
                       final RandomSource randomSource,
                       final int certainty)
        throws ProtocolFormatException {

        if (filenames.length < numberOfInputs + 1) {
            final String e = "There are too few files! ("
                + filenames.length + " < " + (numberOfInputs + 1) + ")";
            throw new ProtocolFormatException(e);
        }

        // Determine input and output filenames.
        final String[] inputFilenames =
            PARSER.getFilenames(filenames, 0, numberOfInputs);
        final String[] outputFilenames =
            PARSER.getFilenames(filenames, numberOfInputs, filenames.length);

        if (format.size() != outputFilenames.length) {
            final String e =
                "The format and number of output filenames do not match!";
            throw new ProtocolFormatException(e);
        }

        // Read input public keys.
        final List<PGroupElement> inputPkeys =
            RAW.readPublicKeys(inputFilenames, randomSource, certainty);

        final List<PGroupElement> outputPkeys =
            rearrangePkeys(inputPkeys, format);

        // Write the public keys to the output files.
        writePublicKeys(outputPkeys, outputFilenames);
    }

    /**
     * Writes public keys to file.
     *
     * @param publicKeys Public keys to be written to file.
     * @param outputFilenames Files to which the public keys are
     * written.
     */
    public static void writePublicKeys(final List<PGroupElement> publicKeys,
                                       final String[] outputFilenames) {

        for (int i = 0; i < outputFilenames.length; i++) {

            final File outputFile = new File(outputFilenames[i]);
            RAW.writePublicKey(publicKeys.get(i), outputFile);
        }
    }

    /**
     * Extract subsequences from a group element array.
     *
     * @param inputPGroup Group to which the input group elements on
     * file should belong.
     * @param interString String representation of a set of
     * subsequences of the input group element array.
     * @param filenames Name of input file and output files.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void subArrays(final PGroup inputPGroup,
                                 final String interString,
                                 final String[] filenames)
        throws ProtocolFormatException {

        // Parse intervals.
        List<ProtocolElGamalRearInterval> intervals = null;
        try {
            intervals = PARSER.parseIntervals(interString);
        } catch (ProtocolFormatException pe) {
            final String e = "Failed to parse intervals! (" + interString + ")";
            throw new ProtocolFormatException(e, pe);
        }

        // Check that there is at least one file and one output file.
        if (filenames.length < 2) {
            final String e =
                String.format("Too few files! (%d < 2)", filenames.length);
            throw new ProtocolFormatException(e);
        }

        // Check that the number of intervals match the number of
        // output filenames.
        if (intervals.size() != filenames.length - 1) {
            final String f =
                "Mismatching number of intervals and output filenames! "
                + "(%d != %d)";
            final String e =
                String.format(f, intervals.size(), filenames.length - 1);
            throw new ProtocolFormatException(e);
        }

        // Read source array.
        final File inputFile = new File(filenames[0]);
        PGroupElementArray inputArray = null;
        try {
            inputArray = RAW.readElementArray(inputPGroup, inputFile);
        } catch (ProtocolFormatException pfe) {
            throw new ProtocolFormatException("Failed to read input array!",
                                              pfe);
        }

        // Extract subarrays.
        final List<PGroupElementArray> outputArrays =
            ProtocolElGamalRear.subArrays(inputArray, intervals);
        final String[] outputFilenames =
            Arrays.copyOfRange(filenames, 1, filenames.length);

        RAW.writeElementArrays(outputArrays, outputFilenames);
    }

    /**
     * Concatenate the arrays in the input files and write the result
     * to the output file.
     *
     * @param inputPGroup Group to which the elements in the input
     * files should belong
     * @param filenames Filenames including the output filename.
     * @throws ProtocolFormatException If the input files do not
     * contain valid arrays.
     */
    public static void catArrays(final PGroup inputPGroup,
                                 final String[] filenames)
        throws ProtocolFormatException {

        if (filenames.length < 2) {
            final String e =
                String.format("Too few files! (%d)", filenames.length);
            throw new ProtocolFormatException(e);
        }

        final String[] inputFilenames =
            Arrays.copyOfRange(filenames, 0, filenames.length - 1);
        final String outputFilename = filenames[filenames.length - 1];

        final PGroupElementArray[] inputArrays =
            new PGroupElementArray[inputFilenames.length];

        for (int i = 0; i < inputFilenames.length; i++) {

            final File file = new File(inputFilenames[i]);
            try {
                inputArrays[i] = RAW.readElementArray(inputPGroup, file);
            } catch (ProtocolFormatException pfe) {
                final String e =
                    "Can not read array from file! (" + inputFilenames[i] + ")";
                throw new ProtocolFormatException(e, pfe);
            }
        }
        final PGroupElementArray array =
            ProtocolElGamalRear.catArrays(inputArrays);
        RAW.writeElementArray(array, new File(outputFilename));
    }

    /**
     * Reads a public key from file.
     *
     * @param pkeyFile File containing public key.
     * @param randomSource Source of randomness.
     * @param certainty Determines the probability that an invalid
     * public key is deemed valid.
     * @return Public key read from file.
     * @throws ProtocolFormatException If the public key can not be read.
     */
    private static PGroupElement readPublicKey(final File pkeyFile,
                                               final RandomSource randomSource,
                                               final int certainty)
        throws ProtocolFormatException {
        try {
            return RAW.readPublicKey(pkeyFile, randomSource, certainty);
        } catch (ProtocolFormatException pfe) {
            final String e = "Failed to read public key!";
            throw new ProtocolFormatException(e, pfe);
        }
    }

    /**
     * Extract widths of product groups to which source group elements
     * (or arrays group elements) must belong.
     *
     * @param opt Command-line options.
     * @param widthsFlag Option string used to pass the widths
     * parameters.
     * @return Widths of product groups to which source group elements
     * must belong.
     * @throws ProtocolFormatException If the width can not be
     * extracted from the command line options.
     */
    public static int[] getWidths(final Opt opt, final String widthsFlag)
        throws ProtocolFormatException {

        final String widthsString = opt.getStringValue(widthsFlag, "");
        if ("".equals(widthsString)) {
            final int[] widths = new int[1];
            widths[0] = 1;
            return widths;
        } else {
            return PARSER.parseWidths(widthsString);
        }
    }

    /**
     * Extract width of input elements.
     *
     * @param opt Command-line options.
     * @return Width of input elements.
     * @throws ProtocolFormatException If the width can not be
     * extracted from the command line options.
     */
    public static int getWidth(final Opt opt)
        throws ProtocolFormatException {

        final int width = opt.getIntValue("-width", 1);
        if (width <= 0) {
            final String e = String.format("Non-positive width! (%d)", width);
            throw new ProtocolFormatException(e);
        }
        return width;
    }

    /**
     * Returns the format specified on the command line.
     *
     * @param opt Command-line options.
     * @return Format used to form group elements or arrays of group
     * elements.
     * @throws ProtocolFormatException If the format can not be
     * extracted from the command line options.
     */
    public static List<List<ProtocolElGamalRearPosition>>
        getFormat(final Opt opt)
        throws ProtocolFormatException {
        return PARSER.parseFormat(opt.getStringValue("-format"));
    }

    /**
     * Returns the number of public keys.
     *
     * @param opt Command-line options.
     * @return Number of public keys.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static int getNumberOfPkeys(final Opt opt)
        throws ProtocolFormatException {
        final int numberOfPkeys = opt.getIntValue("-noin");
        if (numberOfPkeys <= 0) {
            final String e =
                "Non-positive number of public keys! (" + numberOfPkeys + ")";
            throw new ProtocolFormatException(e);
        }
        return numberOfPkeys;
    }

    /**
     * Halts with error code if hidden parameters are not given.
     *
     * @param args Command line arguments.
     */
    public static void sanityCheckHiddenParams(final String[] args) {
        // Parse hidden parameters to wrapper.
        if (args.length < 3) {
            System.err.println("Missing command name or random source "
                               + "parameters!");
            System.exit(1);
        }
    }

    /**
     * Performs a sanity check of the input group element arrays.
     *
     * @param width Width of group elements in the input arrays.
     * @param atomicPGroups Atomic groups for the different group
     * element arrays.
     * @param inputArrays Arrays to be checked.
     * @throws ProtocolFormatException If the input parameters are
     * found to be invalid.
     */
    public static void
        sanityCheckWidthsDeep(final int width,
                              final List<PGroup> atomicPGroups,
                              final List<PGroupElementArray> inputArrays)
        throws ProtocolFormatException {

        // Check that we have as many groups as arrays.
        if (atomicPGroups.size() != inputArrays.size()) {
            final String fm =
                "Mismatching number of groups and group element arrays! "
                + "(%d != %d)";
            final String em =
                String.format(fm, atomicPGroups.size(), inputArrays.size());
            throw new ProtocolFormatException(em);
        }

        for (int i = 0; i < atomicPGroups.size(); i++) {

            final PGroup inputArrayPGroup = inputArrays.get(i).getPGroup();
            final PGroup atomicPGroup = atomicPGroups.get(i);

            final String fa =
                "The %dth group and group element array do not match!";
            final String ea = String.format(fa, i);

            if (width == 1) {

                // Check that if the width is one, then there is no
                // intermediate product group.
                if (!inputArrayPGroup.equals(atomicPGroup)) {
                    throw new ProtocolFormatException(ea);
                }
            } else {

                // Check that the array is defined over a product
                // group.
                if (!(inputArrayPGroup instanceof PPGroup)) {
                    final String epp =
                        "Group element array is not defined over a product "
                        + "group!";
                    throw new ProtocolFormatException(epp);
                }

                final PPGroup pInputArrayPGroup = (PPGroup) inputArrayPGroup;
                final int inputArrayWidth = pInputArrayPGroup.getWidth();

                // Check that the width of the ith group is the given
                // width.
                if (inputArrayWidth != width) {
                    final String fw =
                        "The group of the %dth group element array does not "
                        + "have width %d!";
                    final String ew = String.format(fw, i, width);
                    throw new ProtocolFormatException(ew);
                }

                // Check that the ith atomic group is the same as the
                // atomic group of the ith array.
                for (int j = 0; j < width; j++) {
                    if (!pInputArrayPGroup.project(j).equals(atomicPGroup)) {
                        final String faa =
                            "The %dth atomic group does not match the %dth "
                            + "atomic group over which the array is defined!";
                        final String eaa = String.format(faa, i, i);
                        throw new ProtocolFormatException(eaa);
                    }
                }
            }
        }
    }

    /**
     * Performs a basic sanity check of the input parameters for
     * shallow rearranging.
     *
     * @param widths Widths of the ciphertexts contained in the
     * respective input arrays.
     * @param filenames Input and output filenames.
     * @param format Format describing how to construct the output
     * files.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void
        sanityCheckShallow(final int[] widths,
                           final String[] filenames,
                           final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        final int wl = widths.length;
        final int fl = filenames.length;
        final int fs = format.size();

        if (wl + fs != fl) {
            final String f =
                "The number of widths (%d) plus the number of output "
                + "files (%d) specified in the output format does not "
                + "equal the number of filenames (%d)!";

            throw new ProtocolFormatException(String.format(f, wl, fs, fl));
        }
    }

    /**
     * Performs a basic sanity check of the input parameters for
     * shallow rearranging.
     *
     * @param numberOfPkeys Number of public keys.
     * @param filenames Input and output filenames.
     * @param format Format describing how to construct the output
     * files.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void
        sanityCheckDeep(final int numberOfPkeys,
                        final String[] filenames,
                        final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        final int fl = filenames.length;
        final int fs = format.size();

        if (2 * numberOfPkeys + fs != fl) {
            final String f =
                "The number of public keys (%d) "
                + "plus the number of input group element arrays (%d) "
                + "plus the number of output group element arrays (%d) "
                + "specified in the output format does not "
                + "equal the number of filenames (%d)!";

            final String e =
                String.format(f, numberOfPkeys, numberOfPkeys, fs, fl);
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Check that not both ciphertext and plaintext flags are true.
     *
     * @param ciphs True if and only if ciphertexts are processed.
     * @param plain True if and only if plaintexts are processed.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void sanityCheckNotBothCiphsAndPlain(final boolean ciphs,
                                                       final boolean plain)
        throws ProtocolFormatException {
        if (ciphs && plain) {
            final String e =
                "The options \"-plain\" and \"-ciphs\" can not be combined!";
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Check that at least one input is true.
     *
     * @param ciphs True if and only if ciphertexts are processed.
     * @param plain True if and only if plaintexts are processed.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static void sanityCheckCiphsOrPlain(final boolean ciphs,
                                               final boolean plain)
        throws ProtocolFormatException {
        if (!(ciphs || plain)) {
            final String e =
                "One of the options \"-plain\" or \"-ciphs\" is required!";
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Generates an option instance representing the various ways this
     * protocol an be invoked.
     *
     * @param commandName Name of the command executed by the user to
     * invoke this protocol, i.e., the name of the shell
     * script wrapper.
     * @return Option instance representing how this protocol can be
     * invoked.
     */
    private static Opt opt(final String commandName) {

        final String valueString = "value";
        final String stringString = "string";
        final String defaultErrorString = "Invalid usage form, please use \""
            + commandName + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);

        opt.addParameter("pkey",
                         "Marshalled public key used to determine the group "
                         + "to which ciphertexts or plaintexts belongs.");
        opt.addParameter("file",
                         "Input files and output files in that order. Each "
                         + "file contains a public key, a list of "
                         + "ciphertexts, or a list of plaintexts, depending "
                         + "on which usage form is executed.");

        opt.addOption("-h", "", "Print usage information.");
        opt.addOption("-e", "", "Print stack trace for exceptions.");
        opt.addOption("-cerr", "",
                      "Print error messages as clean strings without any "
                      + "error prefix or newlines.");
        opt.addOption("-version", "", "Print the package version.");
        opt.addOption("-format", stringString,
                      "Describes which components of the objects stored on the "
                      + "input files should be chosen and how they are "
                      + "combined to form the elements written to the output "
                      + "files. "
                      + "The number of input files is derived from the "
                      + "\"-widths\" or \"-noin\" option. "
                      + "\n\n"
                      + "The combination of the input files is viewed "
                      + "as a single two "
                      + "dimensional array, i.e., the content of the ith "
                      + "input file is viewed as the ith source (row). "
                      + "The jth component (column) in the ith "
                      + "source is denoted by (i,j). The sources may have "
                      + "different widths. "
                      + "\n\n"
                      + "The letter \"x\" is used to "
                      + "indicate taking the direct product of components "
                      + "(concatenation), e.g., the "
                      + "following denotes the concatenation of the 2nd "
                      + "component of the 1st input file and the 3rd component "
                      + "from the 4th input file: (0,1)x(3,2). To simplify "
                      + "notation multiple sources/indices may be denoted as "
                      + "\"s-e\", where s is the starting index (inclusive) "
                      + "and e is the "
                      + "ending index (exclusive). "
                      + "\n\n"
                      + "The descriptions of the contents of the output "
                      + "files are separated by "
                      + "colons, e.g., the format \"(0,0-2):(0-1,4)\" "
                      + "states that there are two "
                      + "output files with contents formed as explained "
                      + "above. The number of input files and output files "
                      + "must match the total number of files given as "
                      + "command-line arguments.");
        opt.addOption("-pkeys", "", "Re-arrange public keys.");
        opt.addOption("-ciphs", "", "Re-arrange ciphertexts.");
        opt.addOption("-plain", "", "Re-arrange plaintexts.");
        opt.addOption("-inter", stringString,
                      "Colon separated list of descriptions of intervals, "
                      + "i.e., expressions of the form "
                      + "\"s-e\", where s >= 0 is the inclusive starting index "
                      + "and e > s is the exclusive ending index.");
        opt.addOption("-noin", valueString, "Number of input public keys.");
        opt.addOption("-widths", stringString,
                      "Comma-separated list of widths, e.g., \"2:1:5\". Each "
                      + "width specifies a number of ciphertexts/plaintexts "
                      + "considered as a single block in one of the input "
                      + "arrays. The number of input files is determined "
                      + "from the number of entries in the list of widths.");
        opt.addOption("-width", valueString,
                      "Width that specifies a number of ciphertexts/plaintexts "
                      + "considered as a single block in the input.");
        opt.addOption("-wd", stringString,
                      "Working directory used for file based arrays. This "
                      + "defaults to a uniquely named subdirectory of "
                      + "/tmp/com.verificatum.");
        opt.addOption("-shallow", "",
                      "Re-arrange input arrays according to the given format. "
                      + "One of the options \"-ciphs\" or \"-plain\" is "
                      + "required.");
        opt.addOption("-deep", "",
                      "Re-arrange input arrays according to the given format "
                      + "at the deep level. "
                      + "One of the options \"-ciphs\" or \"-plain\" is "
                      + "required and the width (number of elements or "
                      + "ciphertexts processed in parallel) must be the "
                      + "same for all inputs.");
        opt.addOption("-sub", "",
                      "Split input array into one or more subarrays. One of "
                      + "the options \"-ciphs\" or \"-plain\" is required.");
        opt.addOption("-cat", "",
                      "Concatenate input arrays. This requires that all "
                      + "input arrays are defined relative the same group "
                      + "and width. One of the options \"-ciphs\" or "
                      + "\"-plain\" is required.");

        final String pkeyfile = "pkey,+file#";

        opt.addUsageForm();
        opt.appendToUsageForm(0, "-h###");

        opt.addUsageForm();
        opt.appendToUsageForm(1, "-pkeys,-noin,-format#-e,-cerr,-wd#"
                              + "+pkey#");
        opt.addUsageForm();
        opt.appendToUsageForm(2, "-sub,-inter#"
                              + "-ciphs,-plain,-width,-e,-cerr,-wd#"
                              + pkeyfile);
        opt.addUsageForm();
        opt.appendToUsageForm(3, "-cat#-ciphs,-plain,-width,-e,-cerr,-wd#"
                              + pkeyfile);
        opt.addUsageForm();
        opt.appendToUsageForm(4, "-shallow,-widths,-format#"
                              + "-ciphs,-plain,-e,-cerr,-wd#"
                              + pkeyfile);
        opt.addUsageForm();
        opt.appendToUsageForm(5, "-deep,-noin,-width,-format#"
                              + "-ciphs,-plain,-e,-cerr,-wd#"
                              + pkeyfile);
        opt.addUsageForm();
        opt.appendToUsageForm(6, "-version###");

        final String s =
"WARNING! EXPERIMENTAL COMMAND AT THE MOMENT"
+ "\n\n"
+ "Recall that VMN can process ciphertexts of any keywidth and "
+ "width. This command allows manipulating public keys, ciphertexts, and "
+ "plaintexts to change the keywidth and width and to remove elements or "
+ "combine components from ciphertexts and plaintexts."
+ "\n\n"
+ "For example, one may want to: (a) combine two different public keys, "
+ "(b) shuffle ciphertexts encrypted under the combined key, (c) extract "
+ "only the part encrypted under the first key, and (d) decrypt it. The "
+ "decryption of the other part may be delayed or conditional This "
+ "is easily done using calls to VMN and this command with a suitable "
+ "format."
+ "\n\n"
+ "Public Keys."
+ "\n\n"
+ "Using the \"-pkeys\" option, components of public keys can be combined "
+ "to form new public keys. A standard public key is an element (g,y) in "
+ "G x G, but VMN can also use generalized public keys in G^k x G^k for "
+ "some keywidth k. This can also be viewed as a list of independent "
+ "standard public keys. See examples of different public keys below. The "
+ "components of an element of G^k are indexed from zero."
+ "\n\n"
+ "Arrays of elements of the same type, but different lengths."
+ "\n\n"
+ "The following functionality is available for either arrays "
+ "of ciphertexts or plaintexts depending on if the \"-ciphs\" "
+ "or \"-plain\" flag is used. All arrays must contain, or are generated "
+ "to contain, elements from the same group. Thus, these functions operate "
+ "on complete plaintexts or ciphertexts."
+ "\n\n"
+ "(1) Using the \"-sub\" option, multiple subarrays can be extracted from\n"
+ "    a single source array by providing intervals of indices. The\n"
+ "    intervals are allowed to intersect."
+ "\n\n"
+ "(2) Using the \"-cat\" option arrays can be concatenated, i.e., the\n"
+ "    contents of multiple source arrays with elements of the same\n"
+ "    type are output as a single array."
+ "\n\n"
+ "Arrays of elements of different types, but identical lengths."
+ "\n\n"
+ "Standard plaintexts are elements in G, but VMN can handle more "
+ "complex plaintexts that match the generalized public keys mentioned "
+ "above, i.e., plaintexts may be contained in G^k for some keywidth k "
+ "and the corresponding ciphertexts are contained in G^k x G^k. As "
+ "explained above this corresponds to bundling ciphertexts for multiple "
+ "public keys during processing. One often also want to process a list "
+ "of ciphertexts as a unit. Thus, this is further generalized to "
+ "plaintexts in (G^k)^w and ciphertexts in (G^k)^w x (G^k)^w for some "
+ "width w. This is illustrated below. "
+ "The following functionality is available:"
+ "\n\n"
+ "(1) At the shallow level, we think of G^k as a group H and the components\n"
+ "    of an element in H^w is indexed from zero. Suppose we are given arrays\n"
+ "    of identical lengths containing elements of the same keywidth, but not\n"
+ "    necessarily the same widths. Then the \"-shallow\" option can be used\n"
+ "    to form a new array by picking components at the shallow level from\n"
+ "    the input arrays element-wise and forming elements element-wise."
+ "\n\n"
+ "(2) At the deep level, we consider arrays of elements with identical\n"
+ "    widths, but not necessarily the same keywidth. Using the \"-deep\"\n"
+ "    option, arrays can be formed by picking components at the deep level\n"
+ "    from the input arrays element-wise and forming elements element-wise.\n"
+ "    We stress that this operation is mapped element-wise to the deepest\n"
+ "    level. Elements at the deep level are indexed from zero in the same\n"
+ "    way as for public keys"
+ "\n\n"
+ "Thus, the deep level represents the use of multiple public keys in "
+ "parallel, and the shallow level represents lists of "
+ "ciphertexts and plaintexts that are processed as a unit by the "
+ "mix-net (which may of course be defined over multiple public keys used "
+ "in parallel)."
+ "\n\n"
+ "ILLUSTRATION OF PLAINTEXTS AND PUBLIC KEYS"
+ "\n\n"
+ "Due to the power and complexity of this command we remind the "
+ "user of how public keys, ciphertexts, and plaintexts are represented. "
+ "Consider the following examples:\n"
+ "-----------------------------------------------------    \n"
+ " PUBLIC KEYS:     pk                pk                   \n"
+ "                  / \\             /    \\                 \n"
+ "    pk           g   y           g      y                \n"
+ "    / \\         /|   |\\         /|\\    /|\\               \n"
+ "   g   y       a b   c d       a b c  d e f              \n"
+ "                                                         \n"
+ " keywidth 1    keywidth 2       keywidth 3               \n"
+ "-----------------------------------------------------    \n"
+ " PLAINTEXTS:                         m                   \n"
+ "                                   /    \\                 \n"
+ "                  m               A      B                \n"
+ "                 /|\\             /|\\    /|\\               \n"
+ "     m          a b c           a b c  d e f             \n"
+ "                                                         \n"
+ " keywidth 1  (key)width 3   keywidth 3 & width 2         \n"
+ "-----------------------------------------------------    \n"
+ " CIPHERTEXTS:                          C                 \n"
+ "                                    /     \\              \n"
+ "                  C               U         V            \n"
+ "                 / \\           /   \\       /   \\         \n"
+ "     C          u   v         u     u'    v     v'       \n"
+ "    / \\        /|   |\\       /|\\   /|\\   /|\\   /|\\       \n"
+ "   u   v      a b   c d     a b c d e f g h i j k l      \n"
+ "                                                         \n"
+ " keywidth 1   keywidth 2     keywidth 3 & width 2        \n"
+ "-----------------------------------------------------    \n"
+ "Suppose that the basic prime order group is G. Then in the first "
+ "example the public keys are defined over: G, G^2, and G^3, "
+ "respectively. Similarly, the plaintexts in the second example are "
+ "contained in: G, G^3, and (G^3)^2, respectively. "
+ "Finally, the ciphertexts are contained in: G x G, G^2 x G^2, and "
+ "(G^3)^2 x (G^3)^2, respectively.";

        opt.appendDescription(s);

        return opt;
    }

    /**
     * Parses command line.
     *
     * @param commandName Name of wrapper of tool.
     * @param newargs Command-line arguments.
     * @return Parsed command line arguments.
     * @throws ProtocolFormatException If command line arguments can
     * not be parsed.
     */
    public static Opt parseCommandLine(final String commandName,
                                       final String[] newargs)
        throws ProtocolFormatException {
        final Opt opt = opt(commandName);
        try {
            opt.parse(newargs);
        } catch (OptException oe) {
            throw new ProtocolFormatException(oe.getMessage(), oe);
        }
        return opt;
    }

    /**
     * Command line interface to the rearranging tool.
     *
     * @param args Command line arguments.
     */
    @SuppressWarnings({"PMD.NcssMethodCount",
                       "PMD.CyclomaticComplexity"})
    public static void main(final String[] args) {

        LargeIntegerArray.useFileBased();

        // We must treat the flags -e and -cerr in an ad hoc way to
        // make sure that they work even when parsing the command line
        // fails.
        final boolean cerrFlag = GenUtil.specialFlag("-cerr", args);
        final boolean eFlag = GenUtil.specialFlag("-e", args);

        sanityCheckHiddenParams(args);

        final String commandName = args[0];

        try {

            // Set up random source.
            RandomSource randomSource = null;
            try {
                final File rsFile = new File(args[1]);
                final File seedFile = new File(args[2]);
                final File tmpSeedFile = new File(args[2] + "_TMP");
                randomSource =
                    RandomSource.randomSource(rsFile, seedFile, tmpSeedFile);
            } catch (CryptoException ce) {
                throw new ProtocolError(ce.getMessage(), ce);
            }

            // Remove parameters for wrapper.
            final String[] newargs = Arrays.copyOfRange(args, 3, args.length);

            final Opt opt = parseCommandLine(commandName, newargs);

            OptUtil.processHelpAndVersion(opt);

            try {
                TempFile.init(opt.getStringValue("-wd", ""), randomSource);
            } catch (EIOException eioe) {
                throw new ProtocolFormatException(eioe.getMessage(), eioe);
            }

            final int certainty = ProtocolDefaults.CERTAINTY;

            final String[] filenames = opt.getMultiParameters();


            // Re-arrange public keys.
            if (opt.getBooleanValue("-pkeys")) {

                final int numberOfPkeys = getNumberOfPkeys(opt);
                final List<List<ProtocolElGamalRearPosition>> format =
                    getFormat(opt);

                rearrangePkeys(filenames,
                               numberOfPkeys,
                               format,
                               randomSource,
                               certainty);
                System.exit(0);
            }

            // Extract flags that determine which type of
            // functionality is used.
            final boolean ciphs = opt.getBooleanValue("-ciphs");
            final boolean plain = opt.getBooleanValue("-plain");
            sanityCheckCiphsOrPlain(ciphs, plain);
            sanityCheckNotBothCiphsAndPlain(ciphs, plain);


            // Re-arrange ciphertexts or plaintexts.
            if (opt.getBooleanValue("-deep")) {

                // Width of ciphertexts or plaintexts. All inputs must
                // have the same width.
                final int width = opt.getIntValue("-width", 1);

                final int numberOfPkeys = getNumberOfPkeys(opt);
                final List<List<ProtocolElGamalRearPosition>> format =
                    getFormat(opt);

                sanityCheckDeep(numberOfPkeys, filenames, format);

                final int outputIndex = 2 * numberOfPkeys;
                final String[] pkeyFilenames =
                    PARSER.getFilenames(filenames, 0, numberOfPkeys);
                final String[] inputFilenames =
                    PARSER.getFilenames(filenames, numberOfPkeys, outputIndex);
                final String[] outputFilenames =
                    PARSER.getFilenames(filenames, outputIndex,
                                        filenames.length);

                // Read input public keys.
                final List<PGroupElement> inputPkeysList =
                    RAW.readPublicKeys(pkeyFilenames, randomSource, certainty);
                PGroupElement[] inputPkeys =
                    new PGroupElement[inputPkeysList.size()];
                inputPkeys = inputPkeysList.toArray(inputPkeys);

                final PGroup[] pkeyPGroups = PGroupUtil.getPGroups(inputPkeys);
                final PGroup[] atomicPGroups =
                    RAW.getAtomicPGroups(pkeyPGroups);
                final PGroup primeOrderPGroup =
                    pkeyPGroups[0].getPrimeOrderPGroup();

                if (plain) {

                    final PGroup[] plainPGroups =
                        RAW.getPlainPGroups(atomicPGroups, width);

                    final List<PGroupElementArray> inputArrays =
                        RAW.readArrays(plainPGroups, inputFilenames);

                    final List<PGroupElementArray> outputArrays =
                        ProtocolElGamalRear
                        .rearrangeArraysDeep(width,
                                             primeOrderPGroup,
                                             inputArrays,
                                             format);

                    RAW.writeElementArrays(outputArrays, outputFilenames);

                } else if (ciphs) {


                    System.exit(0);

                    // final PGroup[] ciphPGroups =
                    //     RAW.getCiphPGroups(atomicPGroups, width);

                    // final List<PGroupElementArray> inputArrays =
                    //     RAW.readArrays(ciphPGroups, inputFilenames);

                    //     final List<PGroupElementArray> outputArrays =
                    //      rearrangeCiphs(atomicPGroup, inputArrays, format);

                    //  RAW.writeElementArrays(outputArrays, outputFilenames);

                } else {
                    final String e =
                        "Attempting to use neither ciphertexts nor plaintexts!";
                    throw new ProtocolFormatException(e);
                }
            }


            // Read public key and derive underlying atomic group.
            final File pkeyFile = new File(opt.getStringValue("pkey"));
            final PGroupElement pkey =
                readPublicKey(pkeyFile, randomSource, certainty);
            final PGroup pkeyPGroup = pkey.getPGroup();
            final PGroup atomicPGroup = ((PPGroup) pkeyPGroup).project(0);


            // Re-arrange ciphertexts or plaintexts.
            if (opt.getBooleanValue("-shallow")) {

                final int[] widths = getWidths(opt, "-widths");
                final int numberOfInputs = widths.length;

                final List<List<ProtocolElGamalRearPosition>> format =
                    getFormat(opt);
                sanityCheckShallow(widths, filenames, format);

                final String[] inputFilenames =
                    PARSER.getFilenames(filenames, 0, numberOfInputs);
                final String[] outputFilenames =
                    PARSER.getFilenames(filenames, numberOfInputs,
                                        filenames.length);

                if (plain) {

                    final PGroup[] plainPGroups =
                        RAW.getPlainPGroups(atomicPGroup, widths);

                    final List<PGroupElementArray> inputArrays =
                        RAW.readArrays(plainPGroups, inputFilenames);

                    final List<PGroupElementArray> outputArrays =
                        ProtocolElGamalRear.rearrangeArrays(atomicPGroup,
                                                            inputArrays,
                                                            format);

                    RAW.writeElementArrays(outputArrays, outputFilenames);

                } else if (ciphs) {

                    final PGroup[] ciphPGroups =
                        RAW.getCiphPGroups(atomicPGroup, widths);

                    final List<PGroupElementArray> inputArrays =
                        RAW.readArrays(ciphPGroups, inputFilenames);

                    final List<PGroupElementArray> outputArrays =
                        ProtocolElGamalRear.rearrangeCiphs(atomicPGroup,
                                                           inputArrays,
                                                           format);

                    RAW.writeElementArrays(outputArrays, outputFilenames);

                } else {
                    final String e =
                        "Attempting to use neither ciphertexts nor plaintexts!";
                    throw new ProtocolFormatException(e);
                }

                System.exit(0);
            }


            // Concatenate arrays or extract subarrays.
            final boolean sub = opt.getBooleanValue("-sub");
            final boolean cat = opt.getBooleanValue("-cat");

            if (sub || cat) {

                // Width of ciphertexts or plaintexts.
                final int width = opt.getIntValue("-width", 1);

                // Group to which elements in the array belongs.
                PGroup inputPGroup = null;
                if (plain) {

                    inputPGroup =
                        ProtocolElGamal.getPlainPGroup(atomicPGroup, width);

                } else if (ciphs) {

                    inputPGroup =
                        ProtocolElGamal.getCiphPGroup(atomicPGroup, width);

                } else {
                    final String e =
                        "Attempting to use both ciphertexts and plaintexts!";
                    throw new ProtocolFormatException(e);
                }

                // Extract subarrays.
                if (sub) {

                    final String interString = opt.getStringValue("-inter");
                    subArrays(inputPGroup, interString, filenames);
                    System.exit(0);

                    // Concatenate arrays.
                } else if (cat) {

                    catArrays(inputPGroup, filenames);
                    System.exit(0);

                } else {
                    final String e =
                        "Attempting to both concatenate and extract subarrays!";
                    throw new ProtocolFormatException(e);
                }

                System.exit(0);
            }

        // PMD does not understand this.
        } catch (final ProtocolFormatException pfe) { // NOPMD

            GenUtil.processErrors(pfe, cerrFlag, eFlag);

        } catch (final ProtocolError pe) { // NOPMD

            GenUtil.processErrors(pe, cerrFlag, eFlag);

        } finally {

            TempFile.free();
        }
    }
}
