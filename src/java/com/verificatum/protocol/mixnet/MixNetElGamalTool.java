
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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.Arrays;

import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.TempFile;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.elgamal.ProtocolElGamalInterface;
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory;
import com.verificatum.ui.UI;
import com.verificatum.ui.gen.GenUtil;
import com.verificatum.ui.info.InfoGenerator;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.ui.opt.OptUtil;
import com.verificatum.ui.tui.TConsole;
import com.verificatum.ui.tui.TextualUI;
import com.verificatum.util.PID;
import com.verificatum.util.SimpleTimer;
import com.verificatum.util.UtilException;

/**
 * Implements the command line interface to the mix-net.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalTool {

    /**
     * Name of private info file used if the user does not provide a
     * file name.
     */
    public static final String PRIVINFO_FILENAME = "privInfo.xml";

    /**
     * Name of protocol info file used if the user does not provide a
     * file name.
     */
    public static final String PROTINFO_FILENAME = "protInfo.xml";

    /**
     * Avoid accidental instantiation.
     */
    private MixNetElGamalTool() { }

    /**
     * Default session name.
     */
    static final String DEFAULT_SESSION_NAME = "default";

    /**
     * Factory for interfaces.
     */
    static final ProtocolElGamalInterfaceFactory FACTORY =
        new MixNetElGamalInterfaceFactory();

    /**
     * Raw interface.
     */
    static final ProtocolElGamalInterface RAW_INTERFACE;

    /**
     * Used to time the execution of operations.
     */
    static SimpleTimer timer;

    static {
        try {
            RAW_INTERFACE = FACTORY.getInterface("raw");
        } catch (final ProtocolFormatException pfe) {
            throw new ProtocolError("Unable to get raw interface!", pfe);
        }
    }

    /**
     * Executes the prelude of most operations on the mix-net.
     *
     * @param mixnet Mix-net that is executed.
     */
    protected static void prelude(final MixNetElGamal mixnet) {
        mixnet.startServers();
        timer = new SimpleTimer();
        mixnet.setup();
    }

    /**
     * Executes the prelude of most operations on the mix-net.
     *
     * @param mixnet Mix-net that is executed.
     * @param timerString String used when printing timing information.
     */
    protected static void postlude(final MixNetElGamal mixnet,
                                   final String timerString) {

        mixnet.shutdown(mixnet.getLog());

        final String hline =
            "-----------------------------------------------------------";
        mixnet.getLog().plainInfo(hline);

        mixnet.getLog().plainInfo(String.format("Completed %s.%n",
                                                timerString));



        final long totalExecutionTime = timer.elapsed();
        final long totalNetworkTime = mixnet.getTotalNetworkTime();
        final long totalEffectiveTime = totalExecutionTime - totalNetworkTime;
        final long totalWaitingTime = mixnet.getTotalWaitingTime();
        final long totalCompTime = totalEffectiveTime - totalWaitingTime;

        final long sentBytes = mixnet.getSentBytes();
        final String hSentBytes = ExtIO.bytesToHuman(sentBytes);

        final long receivedBytes = mixnet.getReceivedBytes();
        final String hReceivedBytes = ExtIO.bytesToHuman(receivedBytes);

        final long totalBytes = sentBytes + receivedBytes;
        final String hTotalBytes = ExtIO.bytesToHuman(totalBytes);

        final StringBuilder format = new StringBuilder();
        format.append("Running time:    %13s                 %12s%n");
        format.append("- Execution      %13s                 %12d%n");
        format.append("- Network        %13s                 %12d%n");
        format.append("- Effective      %13s                 %12d%n");
        format.append("- Idle           %13s                 %12d%n");
        format.append("- Computation    %13s                 %12d%n");
        format.append("%n");
        format.append("Communication:   %13s                 %12s%n");
        format.append("- Sent           %13s                 %12d%n");
        format.append("- Received       %13s                 %12d%n");
        format.append("- Total          %13s                 %12d%n");

        final String benchString =
            String.format(format.toString(),
                          " ",
                          "(ms)",
                          SimpleTimer.toString(totalExecutionTime),
                          totalExecutionTime,
                          SimpleTimer.toString(totalNetworkTime),
                          totalNetworkTime,
                          SimpleTimer.toString(totalEffectiveTime),
                          totalEffectiveTime,
                          SimpleTimer.toString(totalWaitingTime),
                          totalWaitingTime,
                          SimpleTimer.toString(totalCompTime),
                          totalCompTime,
                          " ",
                          "(bytes)",
                          hSentBytes,
                          sentBytes,
                          hReceivedBytes,
                          receivedBytes,
                          hTotalBytes,
                          totalBytes);

        mixnet.getLog().plainInfo(benchString);

        // If there is a Fiat-Shamir proof, then we print the size.
        final long nizkpBytes = mixnet.getNizkpBytes();
        if (nizkpBytes > 0) {
            final String hNizkpBytes = ExtIO.bytesToHuman(nizkpBytes);
            final String nizkpString =
                String.format("Proof size:      %13s                 %12d%n",
                              hNizkpBytes, nizkpBytes);

            mixnet.getLog().plainInfo(nizkpString);
        }
    }

    /**
     * Reads the ciphertexts from file.
     *
     * @param mixnet Mix-net that will process the ciphertexts.
     * @param width Width of ciphertexts.
     * @param inputCiphFile File containing input ciphertexts.
     * @return Read ciphertexts.
     * @throws ProtocolFormatException If the the ciphertexts can not
     * be read.
     */
    protected static PGroupElementArray
        readCiphertexts(final MixNetElGamal mixnet,
                        final int width,
                        final File inputCiphFile)
        throws ProtocolFormatException {

        final PGroup ciphPGroup =
            ProtocolElGamal.getCiphPGroup(mixnet.getKeyPGroup(), width);

        final PGroupElementArray ciphertexts =
            RAW_INTERFACE.readCiphertexts(ciphPGroup, inputCiphFile);

        if (ciphertexts.size() == 0) {
            final String e = "No valid ciphertexts were found!";
            throw new ProtocolFormatException(e);
        }
        return ciphertexts;
    }

    /**
     * Writes ciphertexts to the output file.
     *
     * @param mixnet Mix-net that has processed the ciphertexts.
     * @param ciphertexts Ciphertexts to be written.
     * @param outputCiphFile Destination of written ciphertexts.
     */
    protected static void writeCiphertexts(final MixNetElGamal mixnet,
                                           final PGroupElementArray ciphertexts,
                                           final File outputCiphFile) {
        // Import ciphertexts.
        mixnet.getLog().info("Exporting ElGamal ciphertexts.");
        RAW_INTERFACE.writeCiphertexts(ciphertexts, outputCiphFile);
    }

    /**
     * Parse the set of indices.
     *
     * @param s String representation of set of indices.
     * @param k Total number of parties.
     * @param t Threshold number of parties needed to decrypt ciphertexts.
     * @return Array of active parties.
     *
     * @throws ProtocolFormatException If the input string is not valid.
     */
    protected static boolean[] parseActive(final String s, final int k,
                                           final int t)
        throws ProtocolFormatException {
        String e;

        final boolean[] active = new boolean[k + 1];
        Arrays.fill(active, false);

        if (s.length() < 2) {
            e = "Malformed set of indices of " + "active parties! (" + s + ")";
            throw new ProtocolFormatException(e);
        }
        final String a = s.substring(1, s.length() - 1);

        final String[] as = a.split(",");

        int count = 0;
        for (int i = 0; i < as.length; i++) {
            try {

                final int index = Integer.parseInt(as[i]);

                if (active[index]) {
                    e = "Double index! (" + index + ")";
                    throw new ProtocolFormatException(e);
                } else {
                    active[index] = true;
                    count++;
                }

            } catch (final NumberFormatException nfe) {
                e = "Invalid index! (" + as[i] + ")";
                throw new ProtocolFormatException(e, nfe);
            }
        }

        if (count < t) {
            e = "Fewer number of active servers than threshold! "
                + "(" + count + " < " +  t + ")";
            throw new ProtocolFormatException(e);
        }

        return active;
    }

    /**
     * Generates an option instance representing the various ways the
     * mix-net can be invoked.
     *
     * @param commandName Name of the command executed by the user to
     * invoke this protocol, i.e., the name of the shell script
     * wrapper.
     * @return Option instance representing how this protocol can be
     * invoked.
     */
    protected static Opt opt(final String commandName) {

        final String defaultErrorString =
            "Invalid usage form, please use \"" + commandName
            + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);

        opt.addParameter("protInfo", "Protocol info file.");
        opt.addParameter("privInfo", "Private info file.");
        opt.addParameter("publicKey", "Destination of public key.");
        opt.addParameter("ciphertexts", "Ciphertexts to be mixed.");
        opt.addParameter("ciphertextsout", "Mixed ciphertexts.");
        opt.addParameter("plaintexts", "Resulting plaintexts from mixnet.");
        opt.addParameter("indices",
                         "The value must be a set described as "
                         + "a braced comma-separated list of distinct indices, "
                         + "where an index i is an integer 1<=i<=k and k is "
                         + "the total number of parties.");

        opt.addOption("-h", "", "Print usage information.");
        opt.addOption("-s", "",
                      "Silent mode, i.e., do not print any output on stdout.");
        opt.addOption("-e", "", "Print exception trace upon error.");
        opt.addOption("-cerr", "",
                      "Print error messages as clean strings without any "
                      + "error prefix or newlines.");
        opt.addOption("-version", "", "Print the package version.");
        opt.addOption("-keygen", "", "Execute joint key generation.");
        opt.addOption("-setpk", "",
                      "Set an externally generated public key to be used "
                      + "during shuffling (without decrypting). The key must "
                      + "be given in the raw format for the group specified "
                      + "in the info file and with the proper key width. "
                      + "Consider using the vmnc command to convert public "
                      + "keys in other formats.");
        opt.addOption("-precomp", "", "Perform joint pre-computation for a "
                      + "given session.");
        opt.addOption("-maxciph", "value",
                      "Maximal number of ciphertexts for which "
                      + "pre-computation is performed. This defaults to the "
                      + "value given in the protocol info file.");
        opt.addOption("-mix", "",
                      "Mix the input ciphertexts using the given session. If "
                      + "pre-computation was used previously, then the "
                      + "pre-computed values are used to speed up the mixing.");
        opt.addOption("-shuffle", "",
                      "Shuffle the input ciphertexts without decrypting. If "
                      + "pre-computation was used previously, then the "
                      + "pre-computed values are used to speed up the "
                      + "shuffling.");
        opt.addOption("-decrypt", "",
                      "Decrypt the input ciphertexts without mixing.");
        opt.addOption("-auxsid", "sid",
                      "Auxiliary session identifier used to distinguish "
                      + "different sessions of the mix-net. This "
                      + "must consist of letters a-z, A-Z, and digits 0-9. If "
                      + "this option is not used, then the "
                      + "auxiliary session identifier defaults to \""
                      + DEFAULT_SESSION_NAME + "\". Thus, there is a session "
                      + "identifier for every execution.");

        opt.addOption("-lact", "",
                      "List indices of currently active servers.");
        opt.addOption("-sact", "", "Set the set of active mix-servers.");

        opt.addOption("-width", "value",
                      "Number of ciphertexts shuffled as a single block. "
                      + "This defaults to the value in the protocol info "
                      + "file.");
        opt.addOption("-f", "",
                      "Force an interactive option to become non-interactive "
                      + "by silently assuming an affirmative response from "
                      + "the user.");
        opt.addOption("-delete", "",
                      "Delete the given session. "
                      + "WARNING! There is no way to recover the data once it "
                      + "has been deleted.");

        opt.addUsageForm();
        opt.appendToUsageForm(0, "-h###");

        opt.addUsageForm();
        opt.appendToUsageForm(1,
                              "-keygen#-s,-e,-cerr#"
                              + "privInfo,protInfo,publicKey#");

        opt.addUsageForm();
        opt.appendToUsageForm(2, "-mix#-s,-e,-cerr,-auxsid,-width,"
                              + "-maxciph#"
                              + "privInfo,protInfo,"
                              + "ciphertexts,plaintexts#");

        opt.addUsageForm();
        opt.appendToUsageForm(3, "-delete#-s,-e,-cerr,-auxsid,-f#"
                              + "privInfo,protInfo#");

        opt.addUsageForm();
        opt.appendToUsageForm(4, "-lact##privInfo,protInfo#");

        opt.addUsageForm();
        opt.appendToUsageForm(5, "-sact##privInfo,protInfo,indices#");

        opt.addUsageForm();
        opt.appendToUsageForm(6, "-precomp#-s,-e,-cerr,-auxsid,-width,"
                              + "-maxciph#"
                              + "privInfo,protInfo#");

        opt.addUsageForm();
        opt.appendToUsageForm(7, "-setpk#-s,-e,-cerr#"
                              + "privInfo,protInfo,publicKey#");

        opt.addUsageForm();
        opt.appendToUsageForm(8, "-shuffle#-s,-e,-cerr,-auxsid,-width#"
                              + "privInfo,protInfo,"
                              + "ciphertexts,ciphertextsout#");

        opt.addUsageForm();
        opt.appendToUsageForm(9, "-decrypt#-s,-e,-cerr,-auxsid,-width#"
                              + "privInfo,protInfo,"
                              + "ciphertexts,plaintexts#");

        opt.addUsageForm();
        opt.appendToUsageForm(10, "-version###");


        final String s =
            "Executes the various phases of a mix-net."
            + "\n\n"
            + "In all commands, info file names can be dropped in which "
            + "case they are assumed to be \"privInfo.xml\" and "
            + "\"protInfo.xml\" and exist in the current working directory."
            + "\n\n"
            + "Use \"-keygen\" to execute the joint key generation phase of "
            + "the mix-net. This results in a joint public key. All other "
            + "invocations of the mix-net are tied to a particular session "
            + "as determined by the \"-auxsid\" option (or lack thereof in "
            + "which case it defaults to \"default\")."
            + "\n\n"
            + "Use \"-setpk\" to only use the mix-net for shuffling using "
            + "an externally generated public key."
            + "\n\n"
            + "Use \"-mix\" to shuffle and decrypt the input ciphertexts, "
            + "i.e., the output is a list of randomly permuted plaintexts. "
            + "\n\n"
            + "Use \"-shuffle\" to shuffle the input ciphertexts without "
            + "decrypting, i.e., the output is a list of re-encrypted and "
            + "permuted ciphertexts."
            + "\n\n"
            + "If pre-computation was used, then these commands invoke the "
            + "faster process using the pre-computed values."
            + "\n\n"
            + "Use \"-decrypt\" to only execute the decryption phase of the "
            + "mix-net, i.e., no mixing takes place and the output is a list "
            + "of plaintexts."
            + "\n\n"
            + "The shuffling and decryption options can also be used to "
            + "separate the two phases of the mixing process. Together with "
            + "the \"-delete\" option described below this gives a way to "
            + "implement milestones after the pre-computation and after "
            + "shuffling to avoid redundant processing in the event of a "
            + "failure or corruption of a mix-server."
            + "\n\n"
            + "WARNING!\n"
            + "If the mix-net is used in this way, then the user "
            + "must ensure by other means that the input to the decryption "
            + "phase is shuffled by mix-servers of which a sufficient number "
            + "are guaranteed to be uncorrupted."
            + "\n\n"
            + "Use \"-delete\" to completely delete data about a session. "
            + "\n\n"
            + "WARNING!\n"
            + "This removes all data permanently. There is no way to "
            + "recover deleted data. (You can not keep the pre-computed "
            + "data for the shuffling, since this is not necessarily secure "
            + "to re-use.) "
            + "To remain faithful to cryptographic theory YOU MUST CHANGE "
            + "THE AUXILIARY SESSION IDENTIFIER to make sure that no "
            + "encrypted messages are re-used."
            + "\n\n"
            + "Use \"-precomp\" to pre-compute as much as possible of the "
            + "shuffling. Note that this requires interacting with the "
            + "other mix-servers, so all operators must do this simultaneously."
            + "\n\n"
            + "To deal with the case of crashed, corrupted, or isolated "
            + "mix-servers due to accidents, misuse, or corruption, "
            + "individual mix-servers can be deactivated by the remaining "
            + "mix-servers. This allows completing an execution in a secure "
            + "way without these mix-servers. Deactivated mix-servers can be "
            + "re-activated before a later session. Thus, the set of active "
            + "mix-servers can vary throughout the life time to ensure "
            + "maximum robustness."
            + "\n\n"
            + "Use \"-lact\" to print the set of indices of currently "
            + "active mix-servers.\n"
            + "Use \"-sact\" to set the list of indices of currently active "
            + "mix-servers."
            + "\n\n"
            + "The \"-width\" option can be used to set the ciphertext "
            + "width of a session and otherwise it defaults to the width "
            + "from the protocol info file. This corresponds to the number "
            + "of ciphertexts processed as a unit in naively implementations."
            + "\n\n"
            + "The \"-maxciph\" option can be used to set the number of "
            + "ciphertexts for which pre-computation is performed and "
            + "otherwise it defaults to the corresponding value in the "
            + "protocol info file."
            + "\n\n"
            + "Unless the \"-s\" option is used, each invocation of the "
            + "protocol prints logging information not only to the log "
            + "file in the working directory of the mix-server, but also "
            + "to stdout. The time entries of each line in the log file "
            + "must be interpreted with great care, since certain "
            + "operations take place at the same time in separate threads "
            + "and some operations are pre-computed in this way. "
            + "Time measurements are printed at the end of the logging "
            + "information.";

        opt.appendDescription(s);

        return opt;
    }

    /**
     * Return true if and only if the input consists exclusively of
     * letters a-z, A-Z, and digits 0-9.
     *
     * @param s Auxiliary session identifier to be validated.
     * @return True if and only if the input consists exclusively of
     * letters a-z, A-Z, and digits 0-9.
     */
    public static boolean validateAuxsid(final String s) {
        for (int i = 0; i < s.length(); i++) {
            final char c = s.charAt(i);
            if (!('0' <= c && c <= '9'
                  || 'a' <= c && c <= 'z'
                  || 'A' <= c && c <= 'Z')) {
                return false;
            }
        }
        return true;
    }

    /**
     * Derive auxiliary session identifier.
     *
     * @param opt Parsed command line parameters.
     * @return Auxiliary session identifier.
     * @throws ProtocolFormatException If the auxiliary session
     * identifier is invalid.
     */
    private static String processAuxsidString(final Opt opt)
        throws ProtocolFormatException {

        final String auxsidString = opt.getStringValue("-auxsid", "default");

        if (validateAuxsid(auxsidString)) {

            return auxsidString;

        } else {

            final String e = "Session identifiers must only contain characters "
                + "A-Z, a-z, or 0-9!";
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Parses the command line.
     *
     * @param args Command line arguments.
     * @return Parsed command line arguments.
     * @throws ProtocolFormatException If the command line arguments
     * can not be parsed.
     */
    private static Opt parseCommandLine(final String[] args)
        throws ProtocolFormatException {

        if (args.length == 0) {
            throw new ProtocolFormatException("Missing command name!");
        }

        final String commandName = args[0];

        Opt opt = opt(commandName);

        final String[] newargs = Arrays.copyOfRange(args, 1, args.length);

        try {

            opt.parse(newargs);
            return opt;

        } catch (final OptException oe) {

            // If parsing fails, then we assume that the user is
            // executing the commands "in the working directory" and
            // make another attempt with the default file names.

            String task = null;
            if (newargs.length > 0) {
                task = newargs[0];
            } else {
                throw new ProtocolFormatException(oe.getMessage(), oe);
            }

            final String flags =
                "-keygen:-mix:-delete:-lact:-sact:-precomp:-setpk:"
                + "-shuffle:-decrypt";

            if (newargs.length > 0 && flags.indexOf(task) != -1) {

                final String[] newargs2 = new String[newargs.length + 2];
                newargs2[0] = task;
                newargs2[1] = PRIVINFO_FILENAME;
                newargs2[2] = PROTINFO_FILENAME;

                if (newargs.length > 1) {
                    System.arraycopy(newargs,
                                     1,
                                     newargs2,
                                     3,
                                     newargs.length - 1);
                }

                opt = opt(commandName);

                try {

                    opt.parse(newargs2);
                    return opt;

                } catch (final OptException oe2) {

                    // We intentionally drop this exception and use
                    // the original exception instead below.
                    final String e = oe.getMessage();
                    throw new ProtocolFormatException(e, oe); // NOPMD
                }

            } else {

                throw new ProtocolFormatException(oe.getMessage(), oe);
            }
        }
    }

    /**
     * Return true if activity flags are processed and false
     * otherwise.
     *
     * @param mixnet Mixnet.
     * @param opt Parsed command line.
     * @return True or false depending on if the activity flags are
     * processed or not.
     * @throws ProtocolFormatException If the activity flags are invalid.
     */
    private static boolean processActivity(final MixNetElGamal mixnet,
                                           final Opt opt)
        throws ProtocolFormatException {

        // Print representation of currently active mix-servers.
        if (opt.getBooleanValue("-lact")) {

            System.out.println(mixnet.getActiveString());
            return true;
        }

        // Set the set of indices of active parties.
        if (opt.getBooleanValue("-sact")) {

            final boolean[] active = parseActive(opt.getStringValue("indices"),
                                                 mixnet.k,
                                                 mixnet.threshold);
            mixnet.setActive(active);
            return true;
        }

        // If we are not active, the we exit without error.
        return !mixnet.getActive();
    }

    /**
     * Process initialization of the key generator.
     *
     * @param mixnet Mixnet.
     * @param opt Parsed command line.
     * @throws ProtocolFormatException If the parameters are invalid.
     */
    private static void processKeyGen(final MixNetElGamal mixnet,
                                      final Opt opt)
        throws ProtocolFormatException {
        mixnet.writeBoolean(".keygen");

        prelude(mixnet);

        mixnet.generatePublicKey();
        final PGroupElement fullPublicKey = mixnet.getPublicKey();
        final File publicKeyFile = new File(opt.getStringValue("publicKey"));
        RAW_INTERFACE.writePublicKey(fullPublicKey, publicKeyFile);

        postlude(mixnet, "key generation");
    }

    /**
     * Verifies that the width is valid.
     *
     * @param width Width of ciphertexts.
     * @param maxWidth Maximal allowed width of ciphertexts
     * (exclusive). Zero is interpreted as infinity.
     * @return null if the width is valid and otherwise a string
     * description of why it is not.
     */
    public static String validateWidth(final int width, final int maxWidth) {
        if (width <= 0) {
            return "Width is not positive! (" + width + ")";
        }
        if (maxWidth > 0 && width >= maxWidth) {
            return String.format("Width is too big! (%s >= %s)",
                                 width, maxWidth);
        }
        return null;
    }

    /**
     * Derive width from protocol info and command line flag.
     *
     * @param mixnet Mix-net.
     * @param opt Parsed command line.
     * @return Width.
     * @throws ProtocolFormatException If the width is invalid.
     */
    private static int getWidth(final MixNetElGamal mixnet, final Opt opt)
        throws ProtocolFormatException {

        final int width = opt.getIntValue("-width", mixnet.getDefaultWidth());
        final String v = validateWidth(width, 0);
        if (v == null) {
            return width;
        } else {
            throw new ProtocolFormatException(v);
        }
    }

    /**
     * Set up logging.
     *
     * @param mixnet Mix-net.
     * @param ui User interface.
     * @param opt Parsed command line arguments.
     * @throws ProtocolFormatException If the log file does not work.
     */
    private static void setupLogFile(final MixNetElGamal mixnet,
                                     final UI ui,
                                     final Opt opt)
        throws ProtocolFormatException {

        try {
            final File logFile = new File(mixnet.getDirectory(), "log");
            final PrintStream ps =
                new PrintStream(new FileOutputStream(logFile, true));
            ui.getLog().addLogStream(ps);

            if (!opt.getBooleanValue("-s")) {
                ui.getLog().addLogStream(System.out);
            }

        } catch (final FileNotFoundException fnfe) {
            throw new ProtocolFormatException("Can not create log file!", fnfe);
        }
    }

    /**
     * Verifies that key generation is only executed once.
     *
     * @param mixnet Mixnet.
     * @throws ProtocolFormatException If the key generator is invoked twice.
     */
    private static void sanityCheckKeyGen(final MixNetElGamal mixnet)
        throws ProtocolFormatException {

        if (!mixnet.readBoolean(".keygen") && !mixnet.readBoolean(".setpk")) {
            final String e =
                "Either \"-keygen\" or \"-setpk\" must be used first!";
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Verifies that the maximal number ciphertext for which
     * precomputation is performed is positive.
     *
     * @param maxciph Maximal number of ciphertexts.
     * @throws ProtocolFormatException If the maximal number of
     * ciphertexts is not positive.
     */
    private static void sanityCheckMaxciph(final int maxciph)
        throws ProtocolFormatException {

        if (maxciph <= 0) {

            final String e =
                "Non-positive maximal number of ciphertexts! (" + maxciph + ")";
            throw new ProtocolFormatException(e);
        }
    }

    /**
     * Process a request to delete a session.
     *
     * @param auxsidString Auxiliary session identifier.
     * @param mixnet Mix-net.
     * @param opt Parsed command-line arguments.
     * @throws ProtocolFormatException If deletion failed.
     */
    private static void processDelete(final String auxsidString,
                                      final MixNetElGamal mixnet,
                                      final Opt opt)
        throws ProtocolFormatException {

        final String query =
            "WARNING! Deleting a session CAN NOT BE UNDONE later. "
            + "Are you sure that you want to delete?";

        if (opt.getBooleanValue("-f") || mixnet.getUI().dialogQuery(query)) {

            // Note that calling getSession before the mix-net has
            // been setup means that not all properties of the session
            // has been inherited correctly. This is ok here since we
            // only use it for deleting.
            final MixNetElGamalSession session =
                mixnet.getSession(auxsidString);

            session.deleteState();
        }
    }

    /**
     * Process a request to precompute.
     *
     * @param auxsidString Auxiliary session identifier.
     * @param mixnet Mix-net.
     * @param opt Parsed command-line arguments.
     * @param width Width of ciphertexts.
     * @throws ProtocolFormatException If precomputation failed.
     */
    private static void processPrecomp(final String auxsidString,
                                       final MixNetElGamal mixnet,
                                       final Opt opt,
                                       final int width)
        throws ProtocolFormatException {

        final int maxciph =
            opt.getIntValue("-maxciph", mixnet.getDefaultMaxCiph());

        sanityCheckMaxciph(maxciph);

        prelude(mixnet);

        final MixNetElGamalSession session = mixnet.getSession(auxsidString);
        session.precomp(width, maxciph);

        session.free();

        postlude(mixnet, "pre-computation");
    }

    /**
     * Process request to set the public key.
     *
     * @param mixnet Mix-net.
     * @param opt Parsed command line.
     * @throws ProtocolFormatException If setting the public key failed.
     */
    private static void processSetpk(final MixNetElGamal mixnet, final Opt opt)
        throws ProtocolFormatException {

        mixnet.writeBoolean(".setpk");

        final File publicKeyFile = new File(opt.getStringValue("publicKey"));

        final PGroupElement marshalledPublicKey =
            RAW_INTERFACE.readPublicKey(publicKeyFile,
                                        mixnet.randomSource,
                                        mixnet.certainty);

        mixnet.setPublicKey(marshalledPublicKey);
    }

    /**
     * Process request to shuffle ciphertexts.
     *
     * @param auxsidString Auxiliary session identifier.
     * @param mixnet Mix-net.
     * @param opt Parsed command-line arguments.
     * @param width Width of ciphertexts.
     * @param inputCiphertexts Input ciphertexts.
     * @throws ProtocolFormatException If shuffling failed.
     */
    private static void
        processShuffle(final String auxsidString,
                       final MixNetElGamal mixnet,
                       final Opt opt,
                       final int width,
                       final PGroupElementArray inputCiphertexts)
        throws ProtocolFormatException {

        final File outputCiphFile =
            new File(opt.getStringValue("ciphertextsout"));

        prelude(mixnet);

        if (mixnet.readBoolean(".keygen")) {
            mixnet.generatePublicKey();
        }
        final MixNetElGamalSession session = mixnet.getSession(auxsidString);

        final PGroupElementArray outputCiphertexts =
            session.shuffle(width, inputCiphertexts);
        RAW_INTERFACE.writeCiphertexts(outputCiphertexts, outputCiphFile);
        // inputCiphertexts.free();
        outputCiphertexts.free();

        postlude(mixnet, "shuffling");
    }

    /**
     * Process request to mix the input ciphertexts.
     *
     * @param auxsidString Auxiliary session identifier.
     * @param mixnet Mix-net.
     * @param width Width of ciphertexts.
     * @param inputCiphertexts Input ciphertexts.
     * @param plainFile Destination file for plaintexts.
     * @throws ProtocolFormatException If mixing failed.
     */
    private static void processMixing(final String auxsidString,
                                      final MixNetElGamal mixnet,
                                      final int width,
                                      final PGroupElementArray inputCiphertexts,
                                      final File plainFile)
        throws ProtocolFormatException {

        prelude(mixnet);

        mixnet.generatePublicKey();
        final MixNetElGamalSession session = mixnet.getSession(auxsidString);
        final PGroupElementArray plaintexts =
            session.mix(width, inputCiphertexts);
        RAW_INTERFACE.decodePlaintexts(plaintexts, plainFile);

        inputCiphertexts.free();
        plaintexts.free();

        postlude(mixnet, "mixing");
    }

    /**
     * Process request to decrypt the input ciphertexts.
     *
     * @param auxsidString Auxiliary session identifier.
     * @param mixnet Mix-net.
     * @param width Width of ciphertexts.
     * @param inputCiphertexts Input ciphertexts.
     * @param plainFile Destination file for plaintexts.
     */
    private static void
        processDecrypt(final String auxsidString,
                       final MixNetElGamal mixnet,
                       final int width,
                       final PGroupElementArray inputCiphertexts,
                       final File plainFile) {
        prelude(mixnet);

        mixnet.generatePublicKey();
        final MixNetElGamalSession session = mixnet.getSession(auxsidString);
        final PGroupElementArray plaintexts =
            session.decrypt(width, inputCiphertexts);
        RAW_INTERFACE.decodePlaintexts(plaintexts, plainFile);

        inputCiphertexts.free();
        plaintexts.free();

        postlude(mixnet, "decryption");
    }

    /**
     * Checks if any hidden debug should be set.
     *
     * @param opt Turn on suitable debug flags if suitable.
     */
    public static void checkDebug(final Opt opt) {
        if (opt.getDebugBooleanValue("-debugTempFile")) {
            TempFile.debug();
        }
    }

    /**
     * Allows a user to invoke this protocol from the command line.
     *
     * @param args Command line arguments.
     */
    @SuppressWarnings("PMD.CyclomaticComplexity")
    public static void main(final String[] args) {

        if (args.length == 0) {
            System.err.println("Missing parent PID!");
            System.exit(1);
        }
        final String[] newargs = Arrays.copyOfRange(args, 1, args.length);

        // Simple textual user interface.
        final UI ui = new TextualUI(new TConsole());

        // We must treat the flags -e and -cerr in an ad hoc way to
        // make sure that they work even when parsing the command line
        // fails.
        final boolean cerrFlag = GenUtil.specialFlag("-cerr", newargs);
        final boolean eFlag = GenUtil.specialFlag("-e", newargs);

        try {

            final Opt opt = parseCommandLine(newargs);

            // Check for hidden non-documented debug flags.
            checkDebug(opt);

            // If help or version flags are given we act accordingly.
            OptUtil.processHelpAndVersion(opt);

            // Info files.
            final File protocolInfoFile =
                new File(opt.getStringValue("protInfo"));
            final File privateInfoFile =
                new File(opt.getStringValue("privInfo"));

            // Derive info generator.
            final InfoGenerator generator =
                FACTORY.getGenerator(protocolInfoFile);

            // Extract private info.
            final PrivateInfo privateInfo =
                Protocol.getPrivateInfo(generator, privateInfoFile);

            // Extract protocol info.
            final ProtocolInfo protocolInfo =
                Protocol.getProtocolInfo(generator, protocolInfoFile);

            // Create root mix-net.
            final MixNetElGamal mixnet =
                new MixNetElGamal(privateInfo, protocolInfo, ui);

            // Create log file and instruct the logging context of the
            // user interface to write to it.
            setupLogFile(mixnet, ui, opt);

            // Read or set active servers.
            if (processActivity(mixnet, opt)) {
                return;
            }

            // Set public key.
            if (opt.getBooleanValue("-setpk")) {

                processSetpk(mixnet, opt);
                return;
            }
            // try {
            //     new PID(parentPidString, pidFile);
            // } catch (UtilException ue) {
            //     throw new ProtocolFormatException("Failed to create PID file!",
            //                                       ue);
            // }

            // Key generation.
            if (opt.getBooleanValue("-keygen")) {

                processKeyGen(mixnet, opt);
                return;
            }


            // Check that key generation has been executed.
            sanityCheckKeyGen(mixnet);

            // All other commands are executed for a given session.
            final String auxsidString = processAuxsidString(opt);

            // Deleting (parts of) a session.
            if (opt.getBooleanValue("-delete")) {

                processDelete(auxsidString, mixnet, opt);
                return;
            }


            // Determine the width of ciphertexts.
            final int width = getWidth(mixnet, opt);


            // Pre-compute later execute the mix-net.
            if (opt.getBooleanValue("-precomp")) {

                processPrecomp(auxsidString, mixnet, opt, width);
                return;
            }


            // Read the input ciphertexts.
            final File inputCiphFile =
                new File(opt.getStringValue("ciphertexts"));
            final PGroupElementArray inputCiphertexts =
                readCiphertexts(mixnet, width, inputCiphFile);

            // Run shuffling phase only.
            if (opt.getBooleanValue("-shuffle")) {

                processShuffle(auxsidString,
                               mixnet,
                               opt,
                               width,
                               inputCiphertexts);
                return;
            }

            // Destination of plaintexts.
            final File plainFile = new File(opt.getStringValue("plaintexts"));

            // Run mixing phase.
            if (opt.getBooleanValue("-mix")) {

                processMixing(auxsidString,
                              mixnet,
                              width,
                              inputCiphertexts,
                              plainFile);
                return;
            }

            // Run mixing phase.
            if (opt.getBooleanValue("-decrypt")) {

                processDecrypt(auxsidString,
                               mixnet,
                               width,
                               inputCiphertexts,
                               plainFile);
                return;
            }

        // PMD does not understand this.
        } catch (final ProtocolFormatException pfe) { // NOPMD

            GenUtil.processErrors(pfe, cerrFlag, eFlag);

        } finally {
            TempFile.free();
        }
    }
 }
