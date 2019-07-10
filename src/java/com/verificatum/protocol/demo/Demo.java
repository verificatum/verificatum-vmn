
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

package com.verificatum.protocol.demo;

import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.util.Arrays;

import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomDevice;
import com.verificatum.crypto.RandomSource;
import com.verificatum.crypto.SignatureKeyGen;
import com.verificatum.crypto.SignatureKeyGenHeuristic;
import com.verificatum.crypto.SignatureKeyPair;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Hex;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.Protocol;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolDefaults;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.com.BullBoardBasicHTTP;
import com.verificatum.protocol.com.BullBoardBasicHTTPW;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.elgamal.ProtocolElGamalGen;
import com.verificatum.ui.Util;
import com.verificatum.ui.demo.DemoJFrame;
import com.verificatum.ui.gen.GenException;
import com.verificatum.ui.gen.GeneratorTemplate;
import com.verificatum.ui.info.InfoException;
import com.verificatum.ui.info.PartyInfo;
import com.verificatum.ui.info.PartyInfoFactory;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.info.RootInfo;
import com.verificatum.ui.opt.Opt;
import com.verificatum.ui.opt.OptException;
import com.verificatum.vcr.VCR;


/**
 * Demonstrates a protocol by simulating each party as a
 * <code>Runnable</code>. To use this class, the implementor of a
 * protocol must write a factory class implementing the interface
 * {@link DemoProtocolElGamalFactory}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingThrowable"})
public class Demo {

    /**
     * Name of local host parameter.
     */
    public static final String LOCALHOST = "localhost";

    /**
     * Name of host parameter.
     */
    public static final String HOST = "host";

    /**
     * Name of port parameter.
     */
    public static final String PORT = "port";

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
     * Stream where the result of the test is written.
     */
    static PrintStream ps;

    /**
     * Default length of seed to PRG.
     */
    public static final int DEFAULT_SEED_LENGTH = 10000;

    /**
     * Default name of working directory.
     */
    public static final String WORKING_DIRECTORY_NAME = "dir";

    /**
     * Demo directory.
     */
    protected File demoRoot;

    /**
     * Command line options and parameters handed to the demo.
     */
    protected Opt opt;

    /**
     * Protocol factory.
     */
    protected DemoProtocolElGamalFactory factory;

    /**
     * Number of parties.
     */
    protected int k;

    /**
     * Signature key pairs of simulated parties.
     */
    protected SignatureKeyPair[] signatureKeyPairs;

    /**
     * Directories for the parties.
     */
    protected File[] partyDirs;

    /**
     * Creates a demonstrator of a protocol.
     *
     * @param opt Option.
     * @param factory Protocol factory.
     */
    public Demo(final Opt opt, final DemoProtocolElGamalFactory factory) {

        this.opt = opt;
        this.factory = factory;
    }

    /**
     * Set up the configuration for the parties.
     *
     * @throws Exception if setup fails.
     */
    public void setup() throws Exception {

        // Demo directory that holds each party's directory.
        demoRoot = new File(opt.getStringValue("-demoroot"));
        demoRoot = new File(demoRoot, Util.className(factory, true));
        if (!demoRoot.exists()) {
            try {
                ExtIO.mkdirs(demoRoot);
            } catch (final EIOException eioe) {
                throw new DemoError("Unable to create demo root directory!",
                                    eioe);
            }
        }

        // Source of randomness used in this function.
        final RandomDevice randomSource = new RandomDevice();

        // Number of parties.
        k = opt.getIntValue("-k", 3);

        // Signature scheme used to implement bulletin board.
        final SignatureKeyGen signatureKeyGen =
            new SignatureKeyGenHeuristic(ProtocolDefaults.SEC_PARAM);

        // Signature keys of all parties. They are generated here in
        // one place to avoid copying keys.
        signatureKeyPairs = new SignatureKeyPair[k + 1];
        for (int j = 1; j <= k; j++) {
            signatureKeyPairs[j] = signatureKeyGen.gen(randomSource);
        }

        // Directories for all parties.
        partyDirs = new File[k + 1];
        for (int j = 1; j <= k; j++) {
            partyDirs[j] = new File(demoRoot, String.format("Party%02d", j));
            try {
                ExtIO.mkdirs(partyDirs[j]);
            } catch (final EIOException eioe) {
                throw new DemoError("Unable to create directory!", eioe);
            }
        }

        // Generate data for each party.
        for (int j = 1; j <= k; j++) {

            // Create a working for the jth party.
            final File workingDir =
                new File(partyDirs[j], WORKING_DIRECTORY_NAME);
            try {
                ExtIO.mkdirs(workingDir);
            } catch (final EIOException eioe) {
                throw new DemoError("Unable to create working directory!",
                                    eioe);
            }

            // Write seed for PRG.
            final File seedFile = new File(workingDir, Protocol.SEED_FILENAME);
            if (opt.getBooleanValue("-seed")) {
                final byte[] seed = randomSource.getBytes(DEFAULT_SEED_LENGTH);
                final String seedString = Hex.toHexString(seed);
                ExtIO.writeString(seedFile, seedString);
            } else {
                final StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 2 * DEFAULT_SEED_LENGTH; i++) {
                    sb.append(Hex.toHex(i % 16));
                }
                ExtIO.writeString(seedFile, sb.toString());
            }

            // Generate the protocol info file.
            final File protocolInfoFile =
                new File(partyDirs[j], PROTINFO_FILENAME);
            final ProtocolInfo pi =
                factory.generateProtocolInfoFile(this, partyDirs[j],
                                                 protocolInfoFile, opt);

            // Generate the private info file.
            final File privateInfoFile =
                new File(partyDirs[j], PRIVINFO_FILENAME);
            factory.generatePrivateInfoFile(this, partyDirs[j],
                                            privateInfoFile, pi, j, opt);
        }
    }

    /**
     * Execute the protocol.
     *
     * @throws Exception if execution fails.
     */
    public void execute() throws Exception {

        // Instantiate the demo interfaces of all parties
        final DemoJFrame demoJFrame =
            new DemoJFrame(k, factory.getClass().getName());

        // Instantiate the servers.
        final DemoProtocol[] servers = new DemoProtocol[k + 1];
        for (int j = 1; j <= k; j++) {
            final File privateInfoFile =
                new File(partyDirs[j], PRIVINFO_FILENAME);
            final File protocolInfoFile =
                new File(partyDirs[j], PROTINFO_FILENAME);

            servers[j] = factory.newProtocol(privateInfoFile.toString(),
                                             protocolInfoFile.toString(),
                                             demoJFrame.uiAt(j));
        }

        // Decide if we should display the logging or not.
        if (!opt.getBooleanValue("-hide")) {
            demoJFrame.setVisible(true);
        }

        // Execute the parties
        final Thread[] threads = new Thread[k + 1];
        for (int j = 1; j <= k; j++) {
            threads[j] = new Thread(servers[j]);
            threads[j].start();
        }

        // Wait for all servers to complete.
        for (int j = 1; j <= k; j++) {
            threads[j].join();
        }

        // Keep the demo window open if requested.
        if (!opt.getBooleanValue("-hide") && opt.valueIsGiven("-keep")) {
            final int seconds = opt.getIntValue("-keep");
            Thread.sleep(1000 * seconds);
        }

        // Destroy the windows.
        demoJFrame.dispose();

        // Verify that the servers are in a consistent state.
        factory.verify(servers);
    }

    /**
     * Deletes files created by the demo.
     */
    public void delete() {
        if (!opt.getBooleanValue("-nodel")) {

            if (!ExtIO.delete(demoRoot)) {
                throw new DemoError("Unable to delete demo root!");
            }
            try {
                ExtIO.mkdirs(demoRoot);
            } catch (final EIOException eioe) {
                throw new DemoError("Unable to create demo root!", eioe);
            }
        }
    }

    /**
     * Executes the generator template given as input.
     *
     * @param opt Options given by the user.
     * @param optString Option name to extract.
     * @param defString Representation of generator template.
     * @return String representation of generator template.
     */
    public String template(final Opt opt,
                           final String optString,
                           final String defString) {
        try {
            final GeneratorTemplate gt =
                new GeneratorTemplate(GeneratorTemplate.CPY, defString);
            final String gtString = Marshalizer.marshalToHexHuman(gt, true);
            return GeneratorTemplate.execute(opt.getStringValue(optString,
                                                                gtString));
        } catch (final GenException ge) {
            throw new DemoError("Unable to generate from template!", ge);
        }
    }

    /**
     * Normalizes a URL to a fixed format.
     *
     * @param urlString String representing a URL.
     * @return String representing a normalized URL.
     */
    String normalizeURLString(final String urlString) {

        String currentURLString;

        if (urlString.startsWith("http://")) {
            currentURLString = urlString;
        } else {
            currentURLString = "http://" + urlString;
        }

        if (currentURLString.charAt(currentURLString.length() - 1) == '/') {
            currentURLString =
                currentURLString.substring(0, currentURLString.length() - 1);
        }
        return currentURLString;
    }

    /**
     * Initializes the default fields of the input protocol info.
     *
     * @param pi Protocol info.
     * @param opt Options given by the user.
     */
    public void addDefaultValues(final ProtocolInfo pi, final Opt opt) {
        try {
            pi.addValue(Protocol.SID, "DemoID");
            pi.addValue(Protocol.NAME, "DemoName");
            pi.addValue(Protocol.NOPARTIES, opt.getIntValue("-nopart", 3));
            pi.addValue(ProtocolBBT.THRESHOLD, opt.getIntValue("-thres", 2));

            final ProtocolElGamalGen gen = new ProtocolElGamalGen();

            gen.addDefault(pi);
        } catch (InfoException ie) {
            throw new ProtocolError("Failed to add default value!", ie);
        }
    }

    /**
     * Adds default <code>PartyInfo</code> instances to the given
     * <code>ProtocolInfo</code> instance.
     *
     * @param pi Where the <code>PartyInfo</code>'s are added.
     * @param opt Parsed command line options.
     * @throws InfoException if adding default party infos fails.
     */
    public void addDefaultPartyInfos(final ProtocolInfo pi, final Opt opt)
        throws InfoException {

        final int k = opt.getIntValue("-nopart", DemoConstants.NO_PARTIES);

        boolean httpext = false;
        String http = null;
        int httpport = 0;

        if (opt.getBooleanValue("-httpext")) {
            http = opt.getStringValue("-httpext");
            httpext = true;
        } else {
            http = LOCALHOST;
            if (opt.valueIsGiven("-httphost")) {
                http = opt.getStringValue("-httphost");
            }
            httpport =
                opt.getIntValue("-httpport", ProtocolDefaults.HTTP_PORT);
        }

        http = normalizeURLString(http);

        String hinthost = LOCALHOST;
        if (opt.valueIsGiven("-hinthost")) {
            hinthost = opt.getStringValue("-hinthost");
        }
        final int hintport =
            opt.getIntValue("-hintport", ProtocolDefaults.HINT_PORT);

        final PartyInfoFactory pif = pi.getFactory();

        for (int j = 1; j <= k; j++) {
            final PartyInfo p = pif.newInstance();
            p.addValue(Protocol.SORT_BY_ROLE, "DefaultRole");
            p.addValue(Protocol.NAME, String.format("Party%02d", j));
            p.addValue(Protocol.DESCRIPTION, "Description" + j);

            final String pkeyString =
                Marshalizer.marshalToHexHuman(signatureKeyPairs[j].getPKey(),
                                              true);
            p.addValue(BullBoardBasicHTTP.PUB_KEY, pkeyString);

            if (httpext) {
                p.addValue(BullBoardBasicHTTP.HTTP, http + "/Party" + j);
            } else {
                p.addValue(BullBoardBasicHTTP.HTTP, http + ":"
                           + (httpport + j - 1));
            }

            p.addValue(BullBoardBasicHTTPW.HINT, hinthost + ":"
                       + (hintport + j - 1));

            pi.addPartyInfo(p);
        }
    }

    /**
     * Adds some default values to the given <code>PrivateInfo</code>
     * instance.
     *
     * @param pi Where the values are added.
     * @param j Index of party.
     * @param opt Parsed command line options.
     */
    public void addDefaultValues(final PrivateInfo pi,
                                 final int j,
                                 final Opt opt) {

        final String name = String.format("Party%02d", j);
        try {
            pi.addValue(RootInfo.VERSION, VCR.version());
            pi.addValue(Protocol.NAME, name);

            // HTTP server directory used in demonstration.
            final File partyDir = new File(demoRoot, name);
            final File dir = new File(partyDir, WORKING_DIRECTORY_NAME);

            pi.addValue(Protocol.DIRECTORY, dir.toString());

            final File nizkp = new File(dir, "nizkp");
            pi.addValue(ProtocolElGamal.NIZKP, nizkp.toString());

            final String keyPairString =
                Marshalizer.marshalToHexHuman(signatureKeyPairs[j], true);
            pi.addValue(BullBoardBasicHTTP.PRIV_KEY, keyPairString);

            final RandomSource rs = new PRGHeuristic();
            String rsString = Marshalizer.marshalToHexHuman(rs, true);
            if (opt.valueIsGiven("-rs")) {
                try {
                    final String gtString = opt.getStringValue("-rs");
                    final GeneratorTemplate gt =
                        Marshalizer.unmarshalHex_GeneratorTemplate(gtString);
                    rsString = gt.execute();
                } catch (final EIOException eioe) {
                    System.out.println(opt.usage());
                    throw new DemoError("Failed to set up random source!",
                                        eioe);
                } catch (final GenException ge) {
                    System.out.println(opt.usage());
                    throw new DemoError("Failed to set up random source!", ge);
                }
            }
            pi.addValue(Protocol.RANDOMNESS, rsString);

            final int certainty =
                opt.getIntValue("-cert", ProtocolDefaults.CERTAINTY);
            pi.addValue(Protocol.CERTAINTY, certainty);

            pi.addValue("keygen", ProtocolDefaults.CryptoKeyGen());
            pi.addValue("arrays", ProtocolDefaults.ARRAYS);

            File httpdir = new File(partyDir, "http");
            if (opt.valueIsGiven("-httpdir")) {
                httpdir = new File(opt.getStringValue("-httpdir"));
            }
            try {
                ExtIO.mkdirs(httpdir);
            } catch (final EIOException eioe) {
                throw new DemoError("Unable to create directory!", eioe);
            }

            pi.addValue(BullBoardBasicHTTP.HTTPDIR, httpdir.toString());

            String httptype = "internal";
            if (opt.valueIsGiven("-httpext")) {
                httptype = "external";
            }
            pi.addValue(BullBoardBasicHTTP.HTTP_TYPE, httptype);

            String httpl = LOCALHOST;
            if (opt.valueIsGiven("-httphostl")) {
                httpl = opt.getStringValue("-httphostl");
            }
            final int httpportl = opt.getIntValue("-httpportl",
                                                  ProtocolDefaults.HTTP_PORT);
            httpl = normalizeURLString(httpl);
            pi.addValue(BullBoardBasicHTTP.HTTPL, httpl + ":"
                        + (httpportl + j - 1));

            String hinthostl = LOCALHOST;
            if (opt.valueIsGiven("-hinthostl")) {
                hinthostl = opt.getStringValue("-hinthostl");
            }
            final int hintportl = opt.getIntValue("-hintportl",
                                                  ProtocolDefaults.HINT_PORT);
            pi.addValue(BullBoardBasicHTTPW.HINTL, hinthostl + ":"
                        + (hintportl + j - 1));
        } catch (InfoException ie) {
            throw new ProtocolError("Failed to add default value!", ie);
        }
    }

    /**
     * Generates a basic command line parser instance.
     *
     * @param commandName Command name.
     * @return Command line parser.
     */
    public static Opt opt(final String commandName) {

        final String defaultErrorString = "Invalid usage form, please use \""
            + commandName + " -h\" for usage information!";

        final Opt opt = new Opt(commandName, defaultErrorString);

        final String factoryDescription =
            "Demo protocol factories, i.e., a subclasses of "
            + "com.verificatum.protocol.demo.DemoProtocolElGamalFactory that "
            + "demonstrate protocols.";

        opt.addParameter("factory", factoryDescription);

        opt.addOption("-h", "", "Display usage information");
        opt.addOption("-demoroot", "dir", "Root directory for demonstrator. "
                      + "Each demonstrated class is given its own "
                      + "subdirectory.");

        opt.addOption("-nopart", "value", "Number of parties.");
        opt.addOption("-thres", "value", "Threshold number of parties.");

        opt.addOption("-httphost", HOST, "Host address of http servers.");
        opt.addOption("-httpport", PORT,
                      "Offset port number of http servers.");
        opt.addOption("-httphostl", HOST,
                      "Listening host address of http servers.");
        opt.addOption("-httpportl", PORT,
                      "Listening offset port number of http servers.");
        opt.addOption("-httpext", "url", "Use external http server.");

        opt.addOption("-httpdir", "dir",
                      "Prefix of directories of http servers.");

        opt.addOption("-hinthost", HOST,
                      "Hostname of hint server (defaults to \"localhost\").");
        opt.addOption("-hintport", PORT,
                      "Offset port number of hint servers.");
        opt.addOption("-hinthostl", HOST,
                      "Listening hostname of hint server "
                      + "(defaults to \"localhost\").");
        opt.addOption("-hintportl", PORT,
                      "Listening offset port number of hint servers.");

        opt.addOption("-seed", "", "Generate random seed for each party "
                      + "(only works when -rs is not a random device).");
        opt.addOption("-hide", "", "Hide the demonstration window.");
        opt.addOption("-keep", "secs",
                      "Sleep for the given number of seconds inbetween demos, "
                      + "keeping the log windows open. This is ignored if "
                      + "\"-hide\" is used.");
        opt.addOption("-nodel", "",
                      "Do not delete the demo directory. This is "
                      + "useful when debugging.");
        opt.addOption("-rs", "randt", "Randomness template.");

        opt.addUsageForm();
        opt.appendToUsageForm(0, "-h###");
        opt.addUsageForm();
        opt.appendToUsageForm(1, "-demoroot#-hinthost,-hintport,"
                              + "-hinthostl,-hintportl,-httphost,-httpport,"
                              + "-httpext,-httpdir,-httphostl,-httpportl,"
                              + "-seed,-nopart,-thres,-hide,-keep,-nodel,-rs"
                              + "#+factory#");

        final String s =
            "Runs a demonstration including testing the output for each "
            + "factory class given as input.";

        opt.appendDescription(s);

        return opt;
    }

    /**
     * Creates a protocol factory used by the demo to instantiate
     * protocols.
     *
     * @param factoryClassName Name of protocol factory.
     * @return The instantiated factory.
     * @throws Exception If the factory can not be instantiated.
     */
    protected static DemoProtocolElGamalFactory
        factory(final String factoryClassName)
        throws Exception {

        // Instantiate the demo protocol factory.
        final Class<?> klass = Class.forName(factoryClassName);
        final Constructor<?> constructor = klass.getConstructor();
        return (DemoProtocolElGamalFactory) constructor.newInstance();
    }

    /**
     * Command line user interface.
     *
     * @param args Command line arguments.
     */
    public static void main(final String[] args) {

        ps = System.out;

        Demo demo = null;

        try {

            // Parse command line arguments.
            final Opt opt = opt(args[0]);

            try {
                opt.parse(Arrays.copyOfRange(args, 1, args.length));
            } catch (final OptException oe) {
                final String e = "\n" + "ERROR: " + oe.getMessage() + "\n";
                System.err.println(e);
                System.exit(0);
            }

            if (opt.getBooleanValue("-h")) {
                System.out.println(opt.usage());
                System.exit(0);
            }

            // Rudimentary sanity check of command line arguments.
            if (opt.getBooleanValue("-httpext")
                && opt.valueIsGiven("-httphost")
                || opt.valueIsGiven("-httpport")) {
                System.out.println("\nERROR: You may not use both "
                                   + "-httpext and "
                                   + "(-httphost or -httpport).\n");
                System.out.println(opt.usage());
                System.exit(0);
            }

            final String[] factoryClassNames = opt.getMultiParameters();

            int succ = 0;
            ps.println("\nEXECUTING DEMO SEQUENCE ("
                       + factoryClassNames.length + " classes)\n");
            for (final String factoryClassName : factoryClassNames) {
                ps.println(factoryClassName);
            }
            ps.println("");

            final String s =
                "Please be patient. Each demo executes a multiparty "
                + "protocol, so it takes \na while to complete.\n";
            ps.println(s);

            ps.println(String.format("Demo:  Classname:"));
            final String dashes =
                "--------------------------------------------------------";
            ps.println(dashes);

            for (final String factoryClassName : factoryClassNames) {

                ps.print(String.format("%4d   %s... ",
                                       succ + 1,
                                       factoryClassName));

                // Get protocol factory.
                final DemoProtocolElGamalFactory factory =
                    factory(factoryClassName);

                // Run demo.
                demo = new Demo(opt, factory);
                demo.setup();
                demo.execute();
                demo.delete();

                // Increase the number of successfully completed
                // demos.
                succ++;

                ps.println("done.");
            }
            ps.println("\nEXECUTED " + succ + " DEMOS SUCCESSFULLY.\n");
            System.exit(0);

        } catch (final Throwable e) {
            if (demo != null) {
                demo.delete();
            }
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }
}
