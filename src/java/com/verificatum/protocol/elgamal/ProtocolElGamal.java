
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
import java.io.IOException;
import java.util.Arrays;

import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.crypto.CryptoKeyGen;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.crypto.Hashfunction;
import com.verificatum.crypto.HashfunctionHeuristic;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.coinflip.CoinFlipPRingSource;
import com.verificatum.protocol.distr.IndependentGenerator;
import com.verificatum.protocol.distr.PlainKeys;
import com.verificatum.protocol.hvzk.Challenger;
import com.verificatum.protocol.hvzk.ChallengerI;
import com.verificatum.protocol.hvzk.ChallengerRO;
import com.verificatum.ui.Log;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.info.RootInfo;
import com.verificatum.vcr.VCR;


/**
 * Base class for protocols based on the El Gamal cryptosystem. This
 * provides an underlying group, hashfunction used to implement random
 * oracles, distributed key generation, and zero-knowledge proof
 * parameters.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamal extends ProtocolBBT {

    /**
     * String representing SHA 256.
     */
    public static final String SHA256 = "SHA-256";

    /**
     * String representing SHA 384.
     */
    public static final String SHA384 = "SHA-384";

    /**
     * String representing SHA 512.
     */
    public static final String SHA512 = "SHA-512";

    /**
     * Name of non-interactive proof subdirectory tag.
     */
    public static final String NIZKP = "nizkp";

    /**
     * Name of group tag.
     */
    public static final String PGROUP = "pgroup";

    /**
     * Name of key width tag.
     */
    public static final String KEYWIDTH = "keywidth";

    /**
     * Name of tag for bit length of challenge.
     */
    public static final String VBITLEN = "vbitlen";

    /**
     * Name of tag for bit length of challenge when using the
     * Fiat-Shamir heuristic.
     */
    public static final String VBITLENRO = "vbitlenro";

    /**
     * Name of tag for bit length of each component when batching.
     */
    public static final String EBITLEN = "ebitlen";

    /**
     * Name of tag for bit length of each component when batching
     * using the Fiat-Shamir heuristic.
     */
    public static final String EBITLENRO = "ebitlenro";

    /**
     * Name of PRG tag used for batching.
     */
    public static final String PRG = "prg";

    /**
     * Name of tag for hash function used to implement random oracles.
     */
    public static final String ROHASH = "rohash";

    /**
     * Name of tag deciding which type of proofs are used.
     */
    public static final String CORR = "corr";

    /**
     * Name of tag deciding which key generator is used for the
     * encryption scheme used to implement point-wise secret
     * channels.
     */
    public static final String KEYGEN = "keygen";

    /**
     * Name of tag deciding which key generator is used for the
     * encryption scheme.
     */
    public static final String ARRAYS = "arrays";

    /**
     * Width of El Gamal keys.
     */
    protected int keyWidth;

    /**
     * Bit length of challenges in interactive zero-knowledge proofs.
     */
    protected int vbitlen;

    /**
     * Bit length of challenges in non-interactive zero-knowledge
     * proofs.
     */
    protected int vbitlenro;

    /**
     * Bit length of components in random vectors used for batching in
     * interactive zero-knowledge proofs.
     */
    protected int ebitlen;

    /**
     * Bit length of components in random vectors used for batching in
     * non-interactive zero-knowledge proofs.
     */
    protected int ebitlenro;

    /**
     * Indicates if non-interactive zero-knowledge proofs are used or
     * not.
     */
    protected boolean nonInteractiveProofs;

    /**
     * Key generator.
     */
    protected CryptoKeyGen keygen;

    /**
     * Plain public keys used in subprotocols.
     */
    protected CryptoPKey[] pkeys;

    /**
     * Plain secret key used in subprotocols.
     */
    protected CryptoSKey skey;

    /**
     * Description of PRG used for deriving random vectors used for
     * batching in zero-knowledge proofs.
     */
    protected String prgString;

    /**
     * PRG used for deriving random vectors used for batching in
     * zero-knowledge proofs.
     */
    protected PRG prg;

    /**
     * Description of hash function used to implement random oracles.
     */
    protected String roHashfunctionString;

    /**
     * Hash function used to implement random oracles.
     */
    protected Hashfunction roHashfunction;

    /**
     * Description of group over which the protocol is executed.
     */
    protected String pGroupString;

    /**
     * Group over which the protocol is executed.
     */
    protected PGroup pGroup;

    /**
     * Group in which the public key is generated.
     */
    protected PGroup keyPGroup;

    /**
     * Source of jointly generated random bits.
     */
    protected CoinFlipPRingSource coins;

    /**
     * Challenger for zero-knowledge proofs.
     */
    protected Challenger challenger;

    /**
     * Destination directory for universally verifiable proofs.
     */
    protected File nizkp;

    /**
     * Global prefix computed as hash digest of basic parameters to
     * zero-knowledge proofs.
     */
    protected byte[] globalPrefix;

    /**
     * Session identifier used to compute global prefix used in random
     * oracle proofs.
     */
    protected String rosid;

    /**
     * Perform sanity check of auxiliary security parameters.
     *
     * @param vbitlen Bit length of challenges.
     * @param vbitlenro Bit length of challenges when using random oracles.
     * @param ebitlen Bit length of components of batching vectors.
     * @param ebitlenro Bit length of components of batching vectors
     * when using random oracles.
     */
    void sanityCheckAuxSecurityParameters(final int vbitlen,
                                          final int vbitlenro,
                                          final int ebitlen,
                                          final int ebitlenro) {
        if (vbitlen < 128) {
            throw new ProtocolError("Challenge bit length is too small! "
                                    + "("
                                    + vbitlen
                                    + " is less than 160)");
        }
        if (vbitlenro < 256) {
            throw new ProtocolError("Challenge bit length for random "
                                    + "oracles is too small! ("
                                    + vbitlenro
                                    + " is less than 160)");
        }
        if (ebitlen < 128) {
            throw new ProtocolError("Bit length of components of random "
                                    + "batching vector is too small! "
                                    + "(" + ebitlen
                                    + " less than 160 bits)");
        }
        if (ebitlenro < 256) {
            throw new ProtocolError("Bit length of components of random "
                                    + "batching vector for random "
                                    + "oracles is too small! ("
                                    + ebitlenro
                                    + " less than 160 bits)");
        }
    }

    /**
     * Check that the version is correct and matching in infos.
     *
     * @param privateInfo Private info of this party.
     * @param protocolInfo Protocol info of this party.
     */
    private void sanityCheckVersion(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo) {

        final String priVersion = protocolInfo.getStringValue(RootInfo.VERSION);
        final String piVersion = privateInfo.getStringValue(RootInfo.VERSION);
        if (!priVersion.equals(piVersion)
            || !priVersion.equals(VCR.version())) {
            final String e = "Protocol versions in the infos are incompatible "
                + "with each other or with the software version.";
            throw new ProtocolError(e);
        }
    }

    /**
     * Setup the storage model for arrays of elements.
     *
     * @param privateInfo Private info of this party.
     */
    private void setArrayStorageModel(final PrivateInfo privateInfo) {

        final String arraysString = privateInfo.getStringValue(ARRAYS);

        if ("file".equals(arraysString)) {

            LargeIntegerArray.useFileBased();

        } else if (!"ram".equals(arraysString)) {
            final String e =
                "Unknown value (" + arraysString + ") of <arrays></arrays>!";
            throw new ProtocolError(e);
        }
    }

    /**
     * Set up the PRG used to derive batching vectors.
     *
     * @param protocolInfo Protocol info.
     */
    void setupPRG(final ProtocolInfo protocolInfo) {

        prgString = protocolInfo.getStringValue(PRG);

        if (prgString.equals(SHA256)) {
            prg = new PRGHeuristic(new HashfunctionHeuristic(SHA256));
        } else if (prgString.equals(SHA384)) {
            prg = new PRGHeuristic(new HashfunctionHeuristic(SHA384));
        } else if (prgString.equals(SHA512)) {
            prg = new PRGHeuristic(new HashfunctionHeuristic(SHA512));
        } else {
            try {
                prg = Marshalizer.unmarshalHexAux_PRG(prgString,
                                                      randomSource,
                                                      certainty);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to instantiate PRG!", eioe);
            }
        }
    }

    /**
     * Initializes key generator.
     *
     * @param privateInfo Private info of this party.
     */
    private void setupKeyGen(final PrivateInfo privateInfo) {

        final String keygenString = privateInfo.getStringValue(KEYGEN);
        try {
            keygen = Marshalizer.unmarshalHexAux_CryptoKeyGen(keygenString,
                                                              randomSource,
                                                              certainty);
        } catch (final EIOException eioe) {
            throw new ProtocolError("Unable to instantiate key "
                                    + "generator!", eioe);
        }
    }

    /**
     * Initializes underlying group.
     *
     * @param protocolInfo Protocol info of this party.
     */
    private void setupPGroup(final ProtocolInfo protocolInfo) {

        pGroupString = protocolInfo.getStringValue(PGROUP);
        try {
            pGroup = Marshalizer.unmarshalHexAux_PGroup(pGroupString,
                                                        randomSource,
                                                        certainty);
        } catch (final EIOException eioe) {
            throw new ProtocolError("Unable to instantiate group!", eioe);
        }
    }

    /**
     * Initializes hash function used to construct random oracles.
     *
     * @param protocolInfo Protocol info of this party.
     */
    private void setupROHashfunction(final ProtocolInfo protocolInfo) {

        roHashfunctionString = protocolInfo.getStringValue(ROHASH);
        if (roHashfunctionString.equals(SHA256)) {
            roHashfunction = new HashfunctionHeuristic(SHA256);
        } else if (roHashfunctionString.equals(SHA384)) {
            roHashfunction = new HashfunctionHeuristic(SHA384);
        } else if (roHashfunctionString.equals(SHA512)) {
            roHashfunction = new HashfunctionHeuristic(SHA512);
        } else {
            try {
                roHashfunction =
                    Marshalizer.
                    unmarshalHexAux_Hashfunction(roHashfunctionString,
                                                 randomSource,
                                                 certainty);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to instantiate "
                                        + "hash function!", eioe);
            }
        }
    }

    /**
     * Initializes an El Gamal protocol.
     *
     * @param privateInfo Private info of this party.
     * @param protocolInfo Protocol info of this party.
     * @param ui User interface.
     */
    public ProtocolElGamal(final PrivateInfo privateInfo,
                           final ProtocolInfo protocolInfo,
                           final UI ui) {
        super(privateInfo, protocolInfo, ui);

        // Check that the protocol version is correct.
        sanityCheckVersion(privateInfo, protocolInfo);

        // Extract additional security parameters.
        vbitlen = protocolInfo.getIntValue(VBITLEN);
        vbitlenro = protocolInfo.getIntValue(VBITLENRO);
        ebitlen = protocolInfo.getIntValue(EBITLEN);
        ebitlenro = protocolInfo.getIntValue(EBITLENRO);
        sanityCheckAuxSecurityParameters(vbitlen,
                                         vbitlenro,
                                         ebitlen,
                                         ebitlenro);

        // Decide if we are using arrays mapped to files or not.
        setArrayStorageModel(privateInfo);

        // Extract PRG to use to derive random vectors from jointly
        // generateed random seeds in batching.
        setupPRG(protocolInfo);

        // Key generator for keys of the cryptosystem used by
        // subprotocols.
        setupKeyGen(privateInfo);

        // Extract group over which to execute the protocol.
        setupPGroup(protocolInfo);

        // Extract key width.
        keyWidth = protocolInfo.getIntValue(KEYWIDTH);
        if (keyWidth < 1) {
            throw new ProtocolError("Key width is not positive! ("
                                    + keyWidth + ")");
        }
        keyPGroup = getKeyPGroup(pGroup, keyWidth);

        // Hash function used to implement random oracles.
        setupROHashfunction(protocolInfo);

        // Determine if we should use interactive or non-interactive
        // proofs, i.e., the Fiat-Shamir heuristic.
        nonInteractiveProofs =
            "noninteractive".equals(protocolInfo.getStringValue(CORR));

        this.rosid = sid;

        // Initialize global prefix.
        if (nonInteractiveProofs) {
            initGlobalPrefix();
        }

        final String nizkpString = privateInfo.getStringValue(NIZKP);
        if (!nonInteractiveProofs || "".equals(nizkpString)) {
            nizkp = null;
        } else {
            if (nizkpString.charAt(0) == '/') {
                nizkp = new File(nizkpString);
            } else {
                nizkp = new File(directory, nizkpString);
            }
            try {
                ExtIO.mkdirs(nizkp);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to create NIZKP directory!",
                                        eioe);
            }
        }
    }

    /**
     * Initializes an El Gamal protocol as a child of a parent
     * protocol.
     *
     * @param sid Session identifier for this instance.
     * @param prot Protocol that invokes this protocol as a
     * subprotocol.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * #deleteState()} is called.
     */
    public ProtocolElGamal(final String sid,
                           final ProtocolElGamal prot,
                           final String rosid,
                           final File nizkp) {
        super(sid, prot);

        vbitlen = prot.vbitlen;
        vbitlenro = prot.vbitlenro;
        ebitlen = prot.ebitlen;
        ebitlenro = prot.ebitlenro;

        prgString = prot.prgString;
        prg = prot.prg;

        // This is used to indicate that this instance is a child.
        keygen = null;

        pGroupString = prot.pGroupString;
        pGroup = prot.pGroup;
        keyPGroup = prot.keyPGroup;

        roHashfunctionString = prot.roHashfunctionString;
        roHashfunction = prot.roHashfunction;

        nonInteractiveProofs = prot.nonInteractiveProofs;

        pkeys = prot.pkeys;
        skey = prot.skey;

        coins = prot.coins;
        keygen = prot.keygen;

        this.rosid = rosid;

        // Initialize global prefix.
        if (nonInteractiveProofs) {

            if (rosid != null) {
                initGlobalPrefix();
                challenger = new ChallengerRO(roHashfunction, globalPrefix);
            }

        } else {
            challenger = new ChallengerI(coins);
        }

        this.nizkp = nizkp;
        if (nizkp != null) {
            try {
                ExtIO.mkdirs(nizkp);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to create proof directory!",
                                        eioe);
            }
        }
    }

    /**
     * Returns the size of the Fiat-Shamir proof in bytes.
     *
     * @return The size of the Fiat-Shamir proof in bytes, or -1 if
     * none exists.
     */
    public long getNizkpBytes() {
        try {
            if (nizkp == null) {
                return -1;
            } else {
                return ExtIO.fileSize(nizkp);
            }
        } catch (IOException ioe) {
            final String e = "Unable to determine size of proof!";
            throw new ProtocolError(e, ioe);
        }
    }

    @Override
    public void deleteState() {
        super.deleteState();

        if (nizkp != null) {
            ExtIO.delete(nizkp);
        }
    }

    /**
     * Returns the relevant bitlength of challenges. If interactive
     * proofs are used, then this is {@link #vbitlen} and otherwise it
     * is {@link #vbitlenro}.
     *
     * @return Relevant bitlength of challenges.
     */
    protected int vbitlen() {
        if (nonInteractiveProofs) {
            return vbitlenro;
        } else {
            return vbitlen;
        }
    }

    /**
     * Returns the relevant bitlength of components when batching. If
     * interactive proofs are used, then this is {@link #ebitlen} and
     * otherwise it is {@link #ebitlenro}.
     *
     * @return Relevant bitlength of challenges.
     */
    protected int ebitlen() {
        if (nonInteractiveProofs) {
            return ebitlenro;
        } else {
            return ebitlen;
        }
    }

    /**
     * Initializes an El Gamal protocol as a child of a parent
     * protocol.
     *
     * @param sid Session identifier for this instance.
     * @param prot Protocol that invokes this protocol as a
     * subprotocol.
     */
    public ProtocolElGamal(final String sid, final ProtocolElGamal prot) {
        this(sid, prot, null, null);
    }

    /**
     * Initializes the global prefix used as input to non-interactive
     * zero-knowledge proofs.
     */
    protected void initGlobalPrefix() {

        final byte[] packageVersionBytes =
            ExtIO.getBytes(VCR.version());
        final byte[] rosidBytes =
            ExtIO.getBytes(rosid);
        final byte[] prgStringBytes =
            ExtIO.getBytes(prgString);
        final byte[] pGroupBytes =
            ExtIO.getBytes(pGroupString);
        final byte[] roHashfunctionStringBytes =
            ExtIO.getBytes(roHashfunctionString);

        final ByteTree bt =
            new ByteTree(new ByteTree(packageVersionBytes),
                         new ByteTree(rosidBytes),
                         ByteTree.intToByteTree(rbitlen),
                         ByteTree.intToByteTree(vbitlenro),
                         ByteTree.intToByteTree(ebitlenro),
                         new ByteTree(prgStringBytes),
                         new ByteTree(pGroupBytes),
                         new ByteTree(roHashfunctionStringBytes));

        globalPrefix = roHashfunction.hash(bt.toByteArray());
    }

    /**
     * Returns the hash function used to implement random oracles.
     *
     * @return Hash function used to implement random oracles.
     */
    public Hashfunction getROHashfunction() {
        return roHashfunction;
    }

    /**
     * Returns the statistical distance parameter used in this instance.
     *
     * @return Statistical distance parameter used in this instance.
     */
    public int getStatDist() {
        return rbitlen;
    }

    /**
     * Returns the global prefix fed into random oracles.
     *
     * @return Global prefix fed into random oracles.
     */
    public byte[] getGlobalPrefix() {
        return Arrays.copyOf(globalPrefix, globalPrefix.length);
    }

    /**
     * Returns the underlying group of this protocol.
     *
     * @return Underlying group of this protocol.
     */
    public PGroup getPGroup() {
        return pGroup;
    }

    /**
     * Returns the underlying key group of this protocol.
     *
     * @return Underlying group of this protocol.
     */
    public PGroup getKeyPGroup() {
        return keyPGroup;
    }

    /**
     * Generates the key group.
     *
     * @param pGroup Underlying group.
     * @param keyWidth Width of the public key, i.e., how many
     * ordinary El Gamal public keys that are used in parallel.
     * @return Group to which the key belongs.
     */
    public static PGroup getKeyPGroup(final PGroup pGroup, final int keyWidth) {
        if (keyWidth > 1) {
            return new PPGroup(pGroup, keyWidth);
        } else {
            return pGroup;
        }
    }

    /**
     * Returns the group to which plaintexts are expected to belong.
     *
     * @param width Width of plaintexts.
     * @param pGroup Underlying group.
     * @return Ciphertext group.
     */
    public static PGroup getPlainPGroup(final PGroup pGroup, final int width) {
        if (width == 1) {
            return pGroup;
        } else {
            return new PPGroup(pGroup, width);
        }
    }

    /**
     * Returns the group to which ciphertexts are expected to belong.
     * Note that we are using a non-intuitive representation.
     *
     * @param width Width of ciphertext.
     * @param pGroup Underlying group.
     * @return Ciphertext group.
     */
    public static PPGroup getCiphPGroup(final PGroup pGroup, final int width) {
        if (width == 1) {
            return new PPGroup(pGroup, 2);
        } else {
            final PGroup basicPGroup = new PPGroup(pGroup, width);
            return new PPGroup(basicPGroup, 2);
        }
    }

    /**
     * Returns a widened public key.
     *
     * @param fullPublicKey Plain El Gamal public key.
     * @param width Width of public key.
     * @return A public key where both components have been widened.
     */
    public static PPGroupElement
        getWidePublicKey(final PGroupElement fullPublicKey,
                         final int width) {
        if (width == 1) {
            return (PPGroupElement) fullPublicKey;
        } else {
            final PGroupElement g = ((PPGroupElement) fullPublicKey).project(0);
            final PGroupElement y = ((PPGroupElement) fullPublicKey).project(1);

            final PPGroup ciphPGroup = getCiphPGroup(g.getPGroup(), width);
            final PPGroup plainPGroup = (PPGroup) ciphPGroup.project(0);

            return (PPGroupElement) ciphPGroup.product(plainPGroup.product(g),
                                                       plainPGroup.product(y));
        }
    }

    /**
     * Executes the setup phase of the protocol.
     *
     * @param log Logging context.
     */
    public void setup(final Log log) {

        log.info("Generate keys for secret communication.");
        final Log tempLog = log.newChildLog();

        // Generate and exchange keys for a CCA2-secure cryptosystem
        // used for communicating privately.
        PlainKeys plainKeys = new PlainKeys("", this, keygen, rbitlen);
        plainKeys.generate(tempLog);
        pkeys = plainKeys.getPKeys();
        skey = plainKeys.getSKey();

        // Generate an "independent" generator.
        IndependentGenerator ig =
            new IndependentGenerator("", this, pGroup, pkeys, skey, rbitlen);
        final PGroupElement h = ig.generate(tempLog);

        // Construct a source of jointly generated random coins.
        coins = new CoinFlipPRingSource("", this, h, pkeys, skey, rbitlen);

        if (nonInteractiveProofs) {
            challenger = new ChallengerRO(roHashfunction, globalPrefix);
        } else {
            challenger = new ChallengerI(coins);
        }
    }
}
