
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

package com.verificatum.protocol.elgamal;

import java.io.File;
import java.util.Arrays;

import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.Marshalizer;
import com.verificatum.eio.TempFile;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolException;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.ui.gen.GenUtil;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.ui.opt.OptUtil;


/**
 * Generates a file containing encoded El Gamal ciphertexts of
 * numbered dummy messages. This is used for debugging and
 * demonstrations.
 *
 * @author Douglas Wikstrom
 */
public final class ProtocolElGamalDemo {

    /**
     * Avoid accidental instantiation.
     */
    private ProtocolElGamalDemo() { }

    /**
     * Generates an option instance representing the various ways the
     * demo ciphertexts generator can be invoked.
     *
     * @param commandName Name of the command executed by the user to
     * invoke this protocol, i.e., the name of the shell script
     * wrapper.
     * @return Option instance representing how this protocol can be
     * invoked.
     */
    public static Opt opt(final String commandName) {

        final String defaultErrorString =
            "Invalid usage form, please use \"" + commandName
            + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);

        opt.addOption("-pkey", "", "Generate a demo public key.");
        opt.addOption("-ciphs", "", "Generate demo ciphertexts.");

        opt.addParameter("group",
                         "Group over which the protocol is executed. An "
                         + "instance of a subclass of "
                         + "com.verificatum.arithm.PGroup.");
        opt.addParameter("publicKey", "Public key.");
        opt.addParameter("noCiphs", "Number of ciphertexts generated.");
        opt.addParameter("ciphertexts",
                         "Destination of generated ciphertexts.");

        opt.addOption("-h", "", "Print usage information.");
        opt.addOption("-e", "", "Print stack trace for exceptions.");
        opt.addOption("-cerr", "",
                      "Print error messages as clean strings without any "
                      + "error prefix or newlines.");
        opt.addOption("-version", "", "Print the package version.");
        opt.addOption("-keywidth", "value",
                      "Width of El Gamal keys. If equal to one the standard "
                      + "El Gamal cryptosystem is used, but if it is greater "
                      + "than one, then the natural generalization over a "
                      + "product group of the given width is used. This "
                      + "corresponds to letting each party holding multiple "
                      + "standard public keys.");
        opt.addOption("-width", "value",
                      "Width of ciphertexts. This defaults to one.");
        opt.addOption("-wd", "value",
                      "Working directory used for file based arrays. This "
                      + "defaults to a uniquely named subdirectory of "
                      + "/tmp/com.verificatum.");

        opt.addOption("-i", "name",
                      "Protocol interface used to represent the input public "
                      + "key and the output ciphertexts. "
                      + "This defaults to the \"raw\" interface.");

        opt.addUsageForm();
        opt.appendToUsageForm(0, "-h###");

        opt.addUsageForm();
        opt.appendToUsageForm(1, "-pkey#-e,-cerr,-i,-keywidth,-wd#"
                              + "group,publicKey#");

        opt.addUsageForm();
        opt.appendToUsageForm(2, "-ciphs#-e,-cerr,-i,-width,-wd#"
                              + "publicKey,noCiphs,ciphertexts#");

        opt.addUsageForm();
        opt.appendToUsageForm(3, "-version###");

        final String s = "Generates demo ciphertexts for the given interface.";

        opt.appendDescription(s);

        return opt;
    }

    /**
     * Generates a random public key for demonstration purposes.
     *
     * @param pGroup Group over which the public key is generated.
     * @param keyWidth Width of the public key, i.e., how many
     * ordinary El Gamal public keys that are used in parallel.
     * @param randomSource Source of randomness.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution when sampling objects in protocols or in
     * proofs.
     *
     * @return Public key for demonstration purposes.
     */
    protected static PGroupElement
        demoPublicKey(final PGroup pGroup,
                      final int keyWidth,
                      final RandomSource randomSource,
                      final int rbitlen) {

        final PGroup keyPGroup = ProtocolElGamal.getKeyPGroup(pGroup, keyWidth);
        final PPGroup ciphPGroup =
            (PPGroup) ProtocolElGamal.getCiphPGroup(keyPGroup, 1);

        return ciphPGroup.product(keyPGroup.getg(),
                                  keyPGroup.randomElement(randomSource,
                                                          rbitlen));
    }

    /**
     * Return named interface.
     *
     * @param factory Factory for creating interfaces.
     * @param interfaceName Name or nickname of interface.
     * @return Instantiated interface.
     * @throws ProtocolException If the input is not a named
     * interface.
     */
    private static ProtocolElGamalInterface
        getInterface(final ProtocolElGamalInterfaceFactory factory,
                     final String interfaceName)
        throws ProtocolException {

        ProtocolElGamalInterface protInterface = null;
        try {
            protInterface = factory.getInterface(interfaceName);
        } catch (final ProtocolFormatException pfe) {
            throw new ProtocolException("Unable to instantiate interface! ("
                                        + interfaceName + ")", pfe);
        }

        if (!(protInterface instanceof ProtocolElGamalInterfaceDemo)) {

            throw new ProtocolException("The interface does not "
                                        + "support demo ciphertext "
                                        + "generation!");
        }

        return protInterface;
    }

    /**
     * Return group represented by the input.
     *
     * @param pGroupString Representation of the input.
     * @param randomSource Source of randomness.
     * @param certainty Determines the probability that the
     * representation is interpreted incorrectly.
     * @return Instantiated group.
     * @throws ProtocolException If the input does not represent a
     * group.
     */
    private static PGroup getPGroup(final String pGroupString,
                                    final RandomSource randomSource,
                                    final int certainty)
        throws ProtocolException {

        PGroup pGroup = null;
        try {
            pGroup = Marshalizer.unmarshalHexAux_PGroup(pGroupString,
                                                        randomSource,
                                                        certainty);
        } catch (final EIOException eioe) {
            throw new ProtocolException("Unable to instantiate group!", eioe);
        }
        return pGroup;
    }

    /**
     * Returns the named width from the parsed command line interface
     * if it is non-negative.
     *
     * @param widthName Width name that must be either
     * <code>-width</code> or <code>-keywidth</code>
     * @param opt Parsed command line options.
     * @return Verified width from command line parameters.
     * @throws ProtocolException If the width is negative.
     */
    private static int getWidth(final String widthName, final Opt opt)
        throws ProtocolException {

        final int width = opt.getIntValue(widthName, 1);
        if (width < 1) {
            throw new ProtocolException("Width is non-positive!");
        }
        return width;
    }

    /**
     * Setup a working directory.
     *
     * @param protInterface Protocol interface.
     * @param publicKeyFile File containing public key in interface
     * format.
     * @param randomSource Source of randomness.
     * @param certainty Determines the probability that the
     * representation is interpreted incorrectly.
     * @return Read public key.
     * @throws ProtocolException If the public key can not be read.
     */
    private static PGroupElement
        readPublicKey(final ProtocolElGamalInterface protInterface,
                      final File publicKeyFile,
                      final RandomSource randomSource,
                      final int certainty)
        throws ProtocolException {

        PGroupElement fullPublicKey = null;
        try {
            fullPublicKey = protInterface.readPublicKey(publicKeyFile,
                                                        randomSource,
                                                        certainty);
        } catch (final ProtocolFormatException pfe) {
            throw new ProtocolException(pfe.getMessage(), pfe);
        }
        return fullPublicKey;
    }

    /**
     * Command line interface.
     *
     * @param args Command line arguments
     */
    public static void main(final String[] args) {

        final ProtocolElGamalInterfaceFactory factory =
            new ProtocolElGamalInterfaceFactory();

        LargeIntegerArray.useFileBased();

        if (args.length == 0) {
            System.err.println("Missing command name!");
        }
        final Opt opt = opt(args[0]);

        // We must treat the flags -e and -cerr in an ad hoc way to
        // make sure that they work even when parsing the command line
        // fails.
        final boolean cerrFlag = GenUtil.specialFlag("-cerr", args);
        final boolean eFlag = GenUtil.specialFlag("-e", args);

        final String[] remainingArgs = Arrays.copyOfRange(args, 1, args.length);

        try {

            try {
                opt.parse(remainingArgs);
            } catch (final OptException oe) {
                throw new ProtocolException(oe.getMessage(), oe);
            }

            OptUtil.processHelpAndVersion(opt);


            // Instantiate the interface.

            final String interfaceName = opt.getStringValue("-i", "raw");

            final ProtocolElGamalInterface protInterface =
                getInterface(factory, interfaceName);

            final ProtocolElGamalInterfaceDemo protInterfaceDemo =
                (ProtocolElGamalInterfaceDemo) protInterface;

            // For reading a group or a public key.
            final RandomSource randomSource = new PRGHeuristic();
            final int certainty = 100;
            final int rbitlen = 100;
            PGroupElement fullPublicKey = null;

            final File publicKeyFile =
                new File(opt.getStringValue("publicKey"));

            if (opt.valueIsGiven("-pkey")) {

                // Extract group over which to execute the protocol.
                final String pGroupString = opt.getStringValue("group");

                final PGroup pGroup =
                    getPGroup(pGroupString, randomSource, certainty);

                final int keyWidth = getWidth("-keywidth", opt);

                fullPublicKey = demoPublicKey(pGroup,
                                              keyWidth,
                                              randomSource,
                                              rbitlen);

                protInterface.writePublicKey(fullPublicKey, publicKeyFile);

            } else {

                fullPublicKey = readPublicKey(protInterface,
                                              publicKeyFile,
                                              randomSource,
                                              certainty);

                // Expand public key with respect to the width.
                final int width = getWidth("-width", opt);

                // Expand the public key to the given width.
                final PGroupElement widePublicKey =
                    ProtocolElGamal.getWidePublicKey(fullPublicKey, width);

                // Determine number of ciphertexts.
                final int noCiphs = opt.getIntValue("noCiphs");

                // Destination of the ciphertexts.
                final File ciphertexts =
                    new File(opt.getStringValue("ciphertexts"));

                // Initialize demo working directory.
                try {
                    TempFile.init(opt.getStringValue("-wd", ""), randomSource);
                } catch (EIOException eioe) {
                    throw new ProtocolFormatException(eioe.getMessage(), eioe);
                }

                // Generate demo ciphertexts and write them to file.
                protInterfaceDemo.demoCiphertexts(widePublicKey,
                                                  noCiphs,
                                                  ciphertexts,
                                                  randomSource);
            }
        // PMD does not understand this.
        } catch (final ProtocolFormatException pfe) { // NOPMD

            GenUtil.processErrors(pfe, cerrFlag, eFlag);

        } catch (final ProtocolException pe) { // NOPMD

            GenUtil.processErrors(pe, cerrFlag, eFlag);

        } catch (final ProtocolError pe) { // NOPMD

            GenUtil.processErrors(pe, cerrFlag, eFlag);

        } finally {

            TempFile.free();
        }
    }
}
