
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
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.crypto.RandomSource;
import com.verificatum.crypto.CryptoException;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Marshalizer;
import com.verificatum.eio.TempFile;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolDefaults;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.ui.gen.GenUtil;
import com.verificatum.ui.info.InfoGenerator;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.ui.opt.OptUtil;


/**
 * Interface of an El Gamal mix-net. This defines the format of: the
 * public key that is used by senders, the input ciphertexts, and the
 * output plaintexts.
 *
 * @author Douglas Wikstrom
 */
public final class ProtocolElGamalInterfaceTool {

    /**
     * Name of protocol info file used if the user does not provide a
     * file name.
     */
    public static final String PROTINFO_FILENAME = "protInfo.xml";

    /**
     * Avoid accidental instantiation.
     */
    private ProtocolElGamalInterfaceTool() { }

    /**
     * Instantiates the proper factory for instantiating interfaces.
     *
     * @param factoryName Class name of the factory class.
     * @return Named factory.
     */
    protected static ProtocolElGamalInterfaceFactory
        getFactory(final String factoryName) {
        try {

            final Class<?> klass = Class.forName(factoryName);
            final Constructor<?> constructor = klass.getConstructor();

            return (ProtocolElGamalInterfaceFactory) constructor.newInstance();

        } catch (final InvocationTargetException ite) {
            throw new ProtocolError("Unable to interpret, unknown target!",
                                    ite);
        } catch (final InstantiationException ie) {
            throw new ProtocolError("Unable to interpret, unknown target!",
                                    ie);
        } catch (final IllegalAccessException iae) {
            throw new ProtocolError("Unable to interpret, illegal access!",
                                    iae);
        } catch (final ClassNotFoundException cnfe) {
            throw new ProtocolError("Factory class can not be found ("
                                    + factoryName + ")!", cnfe);
        } catch (final NoSuchMethodException nsme) {
            throw new ProtocolError("No appropriate constructor!", nsme);
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
    protected static Opt opt(final String commandName) {

        final String defaultErrorString = "Invalid usage form, please use \""
            + commandName + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);

        opt.addParameter("protInfo", "Protocol info file.");

        opt.addParameter("in", "Source file containing object to convert.");
        opt.addParameter("out", "Destination of converted object.");

        opt.addOption("-h", "", "Print usage information.");
        opt.addOption("-e", "", "Print stack trace for exceptions.");
        opt.addOption("-cerr", "",
                      "Print error messages as clean strings without any "
                      + "error prefix or newlines.");
        opt.addOption("-version", "", "Print the package version.");
        opt.addOption("-ini", "name",
                      "Mix-net interface used to represent the input. "
                      + "This defaults to the \"raw\" interface.");
        opt.addOption("-outi", "name",
                      "Mix-net interface used to represent the output. "
                      + "This defaults to the \"raw\" interface.");
        opt.addOption("-wd", "value",
                      "Working directory used for file based arrays. This "
                      + "defaults to a uniquely named subdirectory of "
                      + "/tmp/com.verificatum.");

        opt.addOption("-sloppy", "",
                      "This changes the behavior such that if the input and "
                      + "output formats are identical, then the contents are "
                      + "copied blindly.");

        opt.addOption("-pkey", "", "Convert public key.");
        opt.addOption("-ciphs", "", "Convert ciphertexts.");
        opt.addOption("-plain", "", "Decode plaintexts.");

        opt.addOption("-width", "value",
                      "Number of ciphertexts considered as a single block. "
                      + "This option overrides the corresponding value in the "
                      + "protocol info file.");

        opt.addUsageForm();
        opt.appendToUsageForm(0, "-h###");

        opt.addUsageForm();
        opt.appendToUsageForm(1, "-pkey#-e,-cerr,-ini,-outi,-wd,-sloppy#"
                              + "protInfo,in,out#");
        opt.addUsageForm();
        opt.appendToUsageForm(2,
                              "-ciphs#-e,-cerr,-ini,-outi,-width,-wd,-sloppy#"
                              + "protInfo,in,out#");
        opt.addUsageForm();
        opt.appendToUsageForm(3,
                              "-plain#-e,-cerr,-outi,-width,-wd,-sloppy#"
                              + "protInfo,in,out#");

        opt.addUsageForm();
        opt.appendToUsageForm(4, "-version###");

        final String s =
            "Converts public keys, ciphertexts, and plaintexts from one "
            + "representation to another. The input and output representations "
            + "are determined by the \"-ini\" and \"-outi\" options."
            + "\n\n"
            + "Possible values of the input and output interfaces are are "
            + "\"raw\", \"native\", or \"json\", or the name of a "
            + "subclass of com.verificatum.protocol.ProtocolElGamalInterface.";

        opt.appendDescription(s);

        return opt;
    }

    /**
     * Initialize working directory.
     *
     * @param commandName Name of wrapper of this class.
     * @param args Command line.
     * @return Parsed command line.
     * @throws ProtocolFormatException If the command line arguments
     * can not be parsed.
     */
    private static Opt parseCommandLine(final String commandName,
                                        final String[] args)
        throws ProtocolFormatException {

        Opt opt = opt(commandName);

        try {

            opt.parse(args);
            return opt;

        } catch (final OptException oe) {

            // If parsing fails, then we assume that the user is
            // executing the commands "in the working directory" and
            // make another attempt with the default file names.

            if (args.length > 3) {

                final String[] newargs = new String[args.length + 1];

                System.arraycopy(args, 0, newargs, 0, args.length - 2);
                newargs[args.length - 2] = PROTINFO_FILENAME;
                System.arraycopy(args, args.length - 2, newargs,
                                 newargs.length - 2, 2);

                opt = opt(commandName);

                try {

                    opt.parse(newargs);
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
     * Derive key width from protocol info.
     *
     * @param protocolInfo Protocol info.
     * @return Key width.
     * @throws ProtocolFormatException If the key width is not positive.
     */
    private static int getKeyWidth(final ProtocolInfo protocolInfo)
        throws ProtocolFormatException {

        final int keyWidth = protocolInfo.getIntValue(ProtocolElGamal.KEYWIDTH);

        if (keyWidth >= 1) {
            return keyWidth;
        } else {
            throw new ProtocolError("Key width is not positive! ("
                                    + keyWidth + ")");
        }
    }

    /**
     * Derive width from protocol info and command line flag.
     *
     * @param protocolInfo Protocol info.
     * @param opt Parsed command line.
     * @return Width.
     * @throws ProtocolFormatException If The width is not valid.
     */
    private static int getWidth(final ProtocolInfo protocolInfo, final Opt opt)
        throws ProtocolFormatException {

        int width = protocolInfo.getIntValue("width");
        width = opt.getIntValue("-width", width);

        if (width <= 0) {
            throw new ProtocolFormatException("Width is not positive! ("
                                              + width + ")");
        }

        return width;
    }

    /**
     * Verifies that this command is executed from a wrapper.
     *
     * @param args Command line parameters.
     */
    public static void sanityCheck(final String[] args) {
        if (args.length < 4) {
            System.err.println("Missing command name, interface factory, "
                               + "or random source parameters!");
            System.exit(1);
        }
    }

    /**
     * Command line interface to the interface tool.
     *
     * @param args Command line arguments.
     */
    @SuppressWarnings("PMD.CyclomaticComplexity")
    public static void main(final String[] args) {

        LargeIntegerArray.useFileBased();

        // We must treat the flags -e and -cerr in an ad hoc way to
        // make sure that they work even when parsing the command line
        // fails.
        final boolean cerrFlag = GenUtil.specialFlag("-cerr", args);
        final boolean eFlag = GenUtil.specialFlag("-e", args);


        // Parse hidden parameters to wrapper.
        sanityCheck(args);
        final String commandName = args[0];

        // Set up factory for interfaces.
        final String factoryName = args[1];
        final ProtocolElGamalInterfaceFactory factory = getFactory(factoryName);

        try {

            // Set up random source.
            RandomSource randomSource = null;
            try {
                final File rsFile = new File(args[2]);
                final File seedFile = new File(args[3]);
                final File tmpSeedFile = new File(args[3] + "_TMP");
                randomSource =
                    RandomSource.randomSource(rsFile, seedFile, tmpSeedFile);
            } catch (CryptoException ce) {
                throw new ProtocolError(ce.getMessage(), ce);
            }

            // Remove parameters to wrapper.
            final String[] newargs = Arrays.copyOfRange(args, 4, args.length);

            final Opt opt = parseCommandLine(commandName, newargs);

            OptUtil.processHelpAndVersion(opt);

            try {
                TempFile.init(opt.getStringValue("-wd", ""), randomSource);
            } catch (EIOException eioe) {
                throw new ProtocolFormatException(eioe.getMessage(), eioe);
            }

            // Configuration of protocol.
            final File protocolInfoFile =
                new File(opt.getStringValue("protInfo"));

            // Determine the info generator.
            final InfoGenerator generator =
                factory.getGenerator(protocolInfoFile);

            // Generate a protocol info and parse the protocol
            // info file.
            final ProtocolInfo protocolInfo =
                Protocol.getProtocolInfo(generator, protocolInfoFile);


            final int certainty = ProtocolDefaults.CERTAINTY;

            // Extract group over which to execute the protocol.
            final String pGroupString =
                protocolInfo.getStringValue(ProtocolElGamal.PGROUP);
            PGroup pGroup = null;
            try {
                pGroup = Marshalizer.unmarshalHexAux_PGroup(pGroupString,
                                                            randomSource,
                                                            certainty);
            } catch (final EIOException eioe) {
                throw new ProtocolFormatException("Invalid group!", eioe);
            }

            // Initialize the handlers of the input format and the
            // output format.
            final String inis = opt.getStringValue("-ini", "raw");
            final ProtocolElGamalInterface ini = factory.getInterface(inis);

            final String outis = opt.getStringValue("-outi", "raw");
            ProtocolElGamalInterface outi;
            if (inis.equals(outis)) {
                outi = ini;
            } else {
                outi = factory.getInterface(outis);
            }

            // Source of data and destination of data.
            final File inf = new File(opt.getStringValue("in"));
            final File outf = new File(opt.getStringValue("out"));


            // If input and output interfaces are identical, then we
            // simply copy the contents blindly in sloppy mode.
            if (ini == outi && opt.getBooleanValue("-sloppy")) {
                try {
                    ExtIO.copyFile(inf, outf);
                } catch (IOException ioe) {
                    final String e = "Unable to blindly copy input to output!";
                    throw new ProtocolFormatException(e, ioe);
                }
                return;
            }


            // Translate public key.
            if (opt.getBooleanValue("-pkey")) {

                final PGroupElement fullPublicKey =
                    ini.readPublicKey(inf, randomSource, certainty);
                outi.writePublicKey(fullPublicKey, outf);
                return;
            }


            // Instantiate group that contains the plaintexts.
            PGroup plainPGroup =
                ProtocolElGamal.getPlainPGroup(pGroup,
                                               getKeyWidth(protocolInfo));

            // Determine actual width.
            final int width = getWidth(protocolInfo, opt);


            // Translate ciphertexts.
            if (opt.getBooleanValue("-ciphs")) {

                final PGroup ciphPGroup =
                    ProtocolElGamal.getCiphPGroup(plainPGroup,
                                                  width);

                final PGroupElementArray ciphertexts =
                    ini.readCiphertexts(ciphPGroup, inf);
                outi.writeCiphertexts(ciphertexts, outf);
                ciphertexts.free();
                return;
            }

            //  plaintext group elements.
            if (opt.getBooleanValue("-plain")) {

                plainPGroup =
                    ProtocolElGamal.getPlainPGroup(plainPGroup, width);

                PGroupElementArray plaintexts = null;
                try {

                    final ByteTreeReader plainReader = new ByteTreeReaderF(inf);
                    plaintexts = plainPGroup.toElementArray(0, plainReader);

                    outi.decodePlaintexts(plaintexts, outf);

                } catch (final ArithmFormatException afe) {
                    throw new ProtocolFormatException(afe.getMessage(), afe);
                } finally {
                    if (plaintexts != null) {
                        plaintexts.free();
                    }
                }
                return;
            }

        // PMD does not understand this.
        } catch (final ProtocolFormatException ppe) { // NOPMD

            GenUtil.processErrors(ppe, cerrFlag, eFlag);

        } catch (final ProtocolError pe) { // NOPMD

            GenUtil.processErrors(pe, cerrFlag, eFlag);

        } finally {

            TempFile.free();
        }
    }
}
