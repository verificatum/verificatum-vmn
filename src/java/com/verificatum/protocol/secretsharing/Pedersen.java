
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

package com.verificatum.protocol.secretsharing;

import java.io.File;
import java.util.Arrays;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupAssociated;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolException;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.ui.Log;


/**
 * Implements a generalized version of Pedersen's Verifiable Secret
 * Sharing (VSS) scheme for arbitrary homomorphisms. This allows
 * receivers to verify their shares and complain if a share is
 * incorrect. The dealer then has the chance of publishing the shares
 * of all complaining parties. If these shares are correct, the
 * sharing is accepted and otherwise it is rejected.
 *
 * <p>
 *
 * This class allows using any {@link HomPRingPGroup} as the
 * underlying homomorphism. Feldman VSS boils down to the
 * exponentiation homomorphism and standard Pedersen VSS boils down to
 * the homomorphism that outputs the exponentiated product of two
 * exponents. The protocol allows reconstruction as long as the
 * underlying homomorphism is collision-resistant. Note that this is
 * the case for the mentioned examples. The hiding property of the
 * protocol depends on how it is used; for Feldman it does not hide
 * the secret perfectly, for standard Pedersen it does, etc.
 *
 * @author Douglas Wikstrom
 */
public final class Pedersen extends ProtocolBBT implements PGroupAssociated {

    /**
     * Underlying functionality.
     */
    PedersenBasic pedersenBasic;

    /**
     * Is set to true when this instance is a "trivial" instance.
     */
    private boolean trivial;

    /**
     * Public keys used for communication.
     */
    private final CryptoPKey[] pkeys;

    /**
     * Secret key of this instance.
     */
    private final CryptoSKey skey;

    /**
     * Index of the dealer in this instance.
     */
    private final int l;

    /**
     * Decides if this instance should store and recover itself
     * automatically to/from file.
     */
    private final boolean storeToFile;

    /**
     * Recovered secret.
     */
    private PRingElement secret;

    /**
     * States in which an instance can be.
     */
    protected enum State {

        /**
         * Initial state of an instantiation.
         */
        INITIAL,

            /**
             * State of the dealer after completed distribution of secret.
             */
            SECRET_DISTRIBUTED,

            /**
             * State of receiver before correctly receiving a share.
             */
            ATTEMPTING_RECEIVE,

            /**
             * State of receiver after receiving a correct share.
             */
            SHARE_RECEIVED,

            /**
             * State after the secret has been recovered.
             */
            SECRET_RECOVERED
            };

    /**
     * Current state of this instance.
     */
    private State state;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    private final int rbitlen;

    /**
     * Creates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param l Index of the dealer.
     * @param hom Underlying homomorphism.
     * @param pkeys Plain public keys of all parties.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param storeToFile Determines if this instance stores/reads
     * itself from/to file.
     */
    public Pedersen(final String sid,
                    final ProtocolBBT protocol,
                    final int l,
                    final HomPRingPGroup hom,
                    final CryptoPKey[] pkeys,
                    final CryptoSKey skey,
                    final int rbitlen,
                    final boolean storeToFile) {
        super(sid, protocol);
        this.state = State.INITIAL;
        pedersenBasic = new PedersenBasic(k, threshold, j, l, hom,
                                          randomSource, rbitlen);
        this.l = l;
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        this.rbitlen = rbitlen;
        trivial = false;
        secret = null;
        this.storeToFile = storeToFile;
    }

    /**
     * Creates an instance of the protocol in a state that allows
     * recovery of the secret.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param l Index of the dealer.
     * @param pkeys Plain public keys of all parties.
     * @param skey Plain secret key.
     * @param pedersenBasic An instance of pedersenBasic.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param storeToFile Determines if this instance stores/reads
     * itself from/to file.
     * @param log Logging context.
     */
    public Pedersen(final String sid,
                    final ProtocolBBT protocol,
                    final int l,
                    final CryptoPKey[] pkeys,
                    final CryptoSKey skey,
                    final PedersenBasic pedersenBasic,
                    final int rbitlen,
                    final boolean storeToFile,
                    final Log log) {
        super(sid, protocol);
        if (j == l) {
            state = State.SECRET_DISTRIBUTED;
        } else {
            state = State.SHARE_RECEIVED;
        }
        this.pedersenBasic = pedersenBasic;
        this.l = l;
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        trivial = false;
        this.storeToFile = storeToFile;
        this.rbitlen = rbitlen;
        this.secret = null;

        if (storeToFile && !stateOnFile()) {
            stateToFile(log);
        }
    }

    /**
     * Returns the instances corresponding to this one over the
     * factors of the underlying {@link Pedersen} instances.
     *
     * @param log Logging context.
     * @return Instances corresponding to this one over the factors of
     * the underlying {@link Pedersen} instances.
     */
    public Pedersen[] getFactors(final Log log) {
        if (state != State.SHARE_RECEIVED
            && state != State.SECRET_DISTRIBUTED) {
            final String s = "Factoring is only possible when recovering is!";
            throw new ProtocolError(s);
        }

        final PedersenBasic[] pedersenBasics = pedersenBasic.getFactors();

        final Pedersen[] pedersens = new Pedersen[pedersenBasics.length];
        for (int i = 0; i < pedersens.length; i++) {
            pedersens[i] =
                new Pedersen(Integer.toString(i),
                             this,
                             l,
                             pkeys,
                             skey,
                             pedersenBasics[i],
                             rbitlen,
                             storeToFile,
                             log);
        }
        return pedersens;
    }

    /**
     * Writes this instance to file.
     *
     * @param log Logging context.
     */
    public void stateToFile(final Log log) {
        ByteTreeBasic bt;

        if (secret == null) {
            bt = new ByteTreeContainer(ByteTree.booleanToByteTree(trivial),
                                       pedersenBasic.stateToByteTree());
        } else {
            bt = new ByteTreeContainer(ByteTree.booleanToByteTree(trivial),
                                       pedersenBasic.stateToByteTree(),
                                       secret.toByteTree());
        }
        log.info("Write state to file.");
        bt.unsafeWriteTo(getFile("State"));
    }

    /**
     * Returns true or false depending on if this instance can find
     * its state on file or not.
     *
     * @return true or false depending on if this instance can find
     * its state on file or not.
     */
    public boolean stateOnFile() {
        final File file = getFile("State");
        return file.exists();
    }

    /**
     * Checks if this instance resides on file. If so it reads its
     * state from file and returns true and otherwise it returns
     * false.
     *
     * @param log Logging context.
     * @return true or false depending on if the state exists and
     * could be read from file or not.
     */
    protected boolean stateFromFile(final Log log) {

        final File file = getFile("State");

        if (file.exists()) {

            ByteTreeReader btr = null;
            log.info("Read state from file.");
            try {
                btr = new ByteTreeReaderF(file);
                trivial = btr.getNextChild().readBoolean();
                pedersenBasic.unsafeStateFromByteTree(btr.getNextChild());
                if (btr.getRemaining() > 0) {
                    secret =
                        pedersenBasic.getPGroup().getPRing().toElement(btr);
                }
                if (j == l) {
                    state = State.SECRET_DISTRIBUTED;
                } else {
                    state = State.SHARE_RECEIVED;
                }

            } catch (final ArithmFormatException afe) {
                throw new ProtocolError("Unable to read secret key!", afe);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to open state file!", eioe);
            } finally {
                if (btr != null) {
                    btr.close();
                }
            }
            return true;

        } else {

            return false;
        }
    }

    /**
     * Shares the secret given as input.
     *
     * @param log Logging context.
     * @param secret Secret to be shared.
     */
    public void dealSecret(final Log log, final PRingElement secret) {

        log.info("Deal a secret using Pedersen VSS.");

        if (!pedersenBasic.getHom().getDomain().equals(secret.getPRing())) {
            throw new ProtocolError("Secret not in domain of homomorphism!");
        }

        if (state != State.INITIAL) {
            throw new ProtocolError("Attempting to reuse instance!");
        }

        final Log tempLog = log.newChildLog();

        // Try to read state from file
        if (storeToFile && stateFromFile(tempLog)) {
            return;
        }

        // Compute sharing.
        tempLog.info("Generate checking elements.");
        pedersenBasic.generateSharing(secret);

        final ByteTreeBasic[] byteTrees = new ByteTreeBasic[k + 1];

        // Add the checking elements.
        byteTrees[0] = pedersenBasic.getPolynomialInExponent().toByteTree();

        // Compute and encrypt the share of each party.
        tempLog.info("Compute encrypted shares for all parties.");
        for (int i = 1; i <= k; i++) {

            // Compute share.
            final PRingElement share = pedersenBasic.computeShare(i);

            // Encode it as a byte[]
            final byte[] shareBytes = share.toByteTree().toByteArray();

            // Encrypt the byte[]. Use the unique full name as a
            // label. This ensures that the ciphertexts of one
            // instance of a protocol can *never* be used in another
            // instance of any protocol. Formally, this ensures that
            // we can reduce the security to the security of the
            // cryptosystem.
            final byte[] bytes = ExtIO.getBytes(getFullName());
            final byte[] ciphertext =
                pkeys[i].encrypt(bytes,
                                 shareBytes,
                                 randomSource,
                                 rbitlen);
            byteTrees[i] = new ByteTree(ciphertext);
        }

        // Write the ByteTree to the bulletin board.
        tempLog.info("Publish checking elements and encrypted shares.");
        bullBoard.publish("Sharing", new ByteTreeContainer(byteTrees), tempLog);

        // Exchange verdicts (we are obviously honest).
        final boolean[] verdicts = exchangeVerdicts(tempLog, true);

        // If somebody complained.
        if (!verdicts[0]) {

            tempLog.info("Somebody complained about their share.");

            // Publish the shares of the complaining parties.
            final ByteTreeBasic[] shares = new ByteTreeBasic[k];
            Arrays.fill(shares, new ByteTree());

            for (int i = 1; i <= k; i++) {
                if (!verdicts[i]) {
                    shares[i - 1] = pedersenBasic.computeShare(i).toByteTree();
                }
            }
            final ByteTreeBasic bt = new ByteTreeContainer(shares);

            tempLog.info("Publish shares of complaining parties.");
            bullBoard.publish("OpenShares", bt, tempLog);
        }

        // Store ourselves to file.
        if (storeToFile) {
            stateToFile(tempLog);
        }

        tempLog.info("Sharing completed.");

        state = State.SECRET_DISTRIBUTED;
    }

    /**
     * Access method for the share of this instance.
     *
     * @return Share of this instance.
     */
    public PRingElement getShare() {
        return pedersenBasic.getShare();
    }

    /**
     * Polynomial encoded in the exponent.
     *
     * @return Polynomial in exponent used.
     */
    public PolynomialInExponent getPolynomialInExponent() {
        return pedersenBasic.getPolynomialInExponent();
    }

    /**
     * Logs header.
     *
     * @param log Logging context.
     * @param l Index of party or zero to indicate the secret was
     * shared secretly.
     */
    public void logInfoReceive(final Log log, final int l) {
        if (l == 0) {
            log.info("Verify jointly generated Pedersen VSS.");
        } else {
            log.info("Verify Pedersen VSS of " + ui.getDescrString(l) + ".");
        }
    }

    /**
     * Verifies that the reader has the right number of components
     * available to read.
     *
     * @param reader Reader to be verified.
     * @throws ProtocolException If the reader has the wrong number of
     * components available for reading.
     */
    private void checkNumberOfComponents(final ByteTreeReader reader)
        throws ProtocolException {

        final int r = reader.getRemaining();

        if (r != k + 1) {

            final String e = String.format("Wrong number of components! "
                                           + "(expected %d, but found %d)",
                                           k + 1, r);
            throw new ProtocolException(e);
        }
    }

    /**
     * Reads a polynomial in the exponent from the reader and
     * initializes the underlying implementation of the Pedersen VSS
     * with it.
     *
     * @param reader Source of the polynomial in the exponent.
     * @throws ProtocolException If a correct polynomial can not be
     * read.
     * @return Polynomial in exponent read.
     */
    private PolynomialInExponent
        readPolynomialInExponent(final ByteTreeReader reader)
        throws ProtocolException {

        Exception fe = null;
        try {
            return new PolynomialInExponent(pedersenBasic.getHom(),
                                            threshold - 1,
                                            reader.getNextChild());

        } catch (final ProtocolFormatException pfe) {
            fe = pfe;
        } catch (final EIOException eioe) {
            fe = eioe;
        }

        final String e =
            "Unable to read polynomial in exponent from byte tree!";
        throw new ProtocolException(e, fe);
    }

    /**
     * Skips the given number of children in the reader.
     *
     * @param reader Source of children.
     * @param j Position we wish to reach where this position is zero.
     * @throws ProtocolException If there are too few children.
     */
    private void skipChildren(final ByteTreeReader reader, final int j)
        throws ProtocolException {
        try {
            reader.skipChildren(j - 1);
        } catch (final EIOException eioe) {
            throw new ProtocolException("Unable to skip shares!", eioe);
        }
    }

    /**
     * Reads a ciphertext as a byte array.
     *
     * @param reader Source of the ciphertext.
     * @return Ciphertext read.
     * @throws ProtocolException If a ciphertext can not be read.
     */
    private byte[] readCiphertext(final ByteTreeReader reader)
        throws ProtocolException {

        try {

            return reader.getNextChild().read();

        } catch (final EIOException eioe) {

            throw new ProtocolException("Unable to read ciphertext!", eioe);
        }
    }

    /**
     * Decrypts a ciphertext using our secret key.
     *
     * @param ciphertext Ciphertext to be decrypted.
     * @return Plaintext hidden in ciphertext.
     * @throws ProtocolException If the ciphertext is invalid.
     */
    private byte[] decryptCiphertext(final byte[] ciphertext)
        throws ProtocolException {

        final byte[] labelBytes = ExtIO.getBytes(getFullName());
        final byte[] plaintext = skey.decrypt(labelBytes, ciphertext);

        if (plaintext == null) {
            throw new ProtocolException("Invalid ciphertext!");
        }  else {
            return plaintext;
        }
    }

    /**
     * Decodes a plaintext byte array into a ring element.
     *
     * @param sharePRing Ring to which the decoded ring element must
     * belong.
     * @param plaintext Plaintext to be decoded.
     * @return Plaintext ring element encoded in the byte array
     * plaintext.
     * @throws ProtocolException If the plaintext can not be decoded
     * into a ring element.
     */
    private PRingElement decodePlaintext(final PRing sharePRing,
                                         final byte[] plaintext)
        throws ProtocolException {

        try {

            final ByteTreeReader btr =
                new ByteTree(plaintext, null).getByteTreeReader();
            return sharePRing.toElement(btr);

        } catch (final EIOException eio) {
            throw new ProtocolException("Share plaintextis not a byte tree!",
                                        eio);
        } catch (final ArithmFormatException afe) {
            throw new ProtocolException("Share byte tree does not "
                                        + "encode a ring element!", afe);
        }
    }

    /**
     * Receives our share and initializes the underlying Pedersen VSS
     * with it.
     *
     * @param log Logging context.
     * @return True or false depending on if our share is correct or
     * not in the case where this is not determined by all parties in
     * agreement.
     * @throws ProtocolException If all parties are in agreement that
     * the shares are wrong.
     */
    private boolean receiveOurShare(final Log log) throws ProtocolException {

        ByteTreeReader reader = null;

        try {

            // Wait for polynomial in the exponent and encrypted shares.
            log.info("Read checking elements and ciphertexts from "
                     + ui.getDescrString(l) + ".");
            reader = bullBoard.waitFor(l, "Sharing", log);

            // If the number of components is wrong, then all parties
            // agree on this and we throw an exception in agreement.
            checkNumberOfComponents(reader);

            // If the checking data is incorrect, then all parties
            // agree on this and we throw an exception in agreement.
            try {
                final PolynomialInExponent pie =
                    readPolynomialInExponent(reader);
                pedersenBasic.setPolynomialInExponent(pie);
            } catch (final ProtocolFormatException pfe) {
                throw new ProtocolException("Malformed checking parameters!",
                                            pfe);
            }

            PRingElement share;
            try {
                // Move to the encryption of our share.
                skipChildren(reader, j);

                // Read ciphertext.
                final byte[] ciphertext = readCiphertext(reader);

                // Decrypt ciphertext
                final byte[] plaintext = decryptCiphertext(ciphertext);

                // Ring containing the shares.
                final PRing sharePRing = pedersenBasic.getHom().getDomain();

                // Decode our share
                share = decodePlaintext(sharePRing, plaintext);

           // PMD does not understand that this is a clean way to
           // handle control flow.
            } catch (final ProtocolException pe) { // NOPMD
                log.info(pe.getMessage());
                return false;
            }

            // Verify our share
            pedersenBasic.setShare(share);
            if (pedersenBasic.verifyShare()) {

                log.info("Our share is correct.");
                return true;
            } else {

                log.info("Our share is incorrect.");
                return false;
            }

        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    /**
     * Skips one child in the reader.
     *
     * @param reader Reader containing child.
     * @throws ProtocolException If the reader does not contain a
     * child to be skipped.
     */
    private void skipChild(final ByteTreeReader reader)
        throws ProtocolException {
        try {
            reader.skipChild();
        } catch (final EIOException eioe) {

            throw new ProtocolException("Unable to skip child!", eioe);
        }
    }

    /**
     * Reads and verifies a share of a given party other than this
     * party.
     *
     * @param reader Reader containing child.
     * @param i Index of party to which the share belongs.
     * @param log Logging context.
     * @throws ProtocolException If the share of the given party can
     * not be read or verified.
     */
    private void readAndVerifyShare(final ByteTreeReader reader,
                                    final int i,
                                    final Log log)
        throws ProtocolException {
        try {

            // Read share.
            final PRingElement share = pedersenBasic.getHom().getDomain()
                .toElement(reader.getNextChild());

            // Verify that the share was correctly computed for the
            // ith party.
            if (pedersenBasic.verifyShare(i, share)) {
                log.info("Opened share of " + ui.getDescrString(i)
                         + " is correct.");

                // If this was a corrected share for us, then we must
                // keep it.
                if (i == j) {
                    pedersenBasic.setShare(share);
                }

            } else {
                throw new ProtocolException("Opened share of "
                                            + ui.getDescrString(i)
                                            + " is incorrect!");
            }

        } catch (final EIOException eioe) {

            throw new ProtocolException("Unable to read share!", eioe);

        } catch (final ArithmFormatException afe) {

            throw new ProtocolException("Malformed share!", afe);
        }
    }

    /**
     * Reads and verifies that the shares revealed by the dealer to
     * refute complaints are correct.
     *
     * @param verdicts Verdicts of the receivers regarding the shares
     * they received from the dealer.
     * @param log Logging context.
     * @throws ProtocolException If the dealer fails to reveal valid
     * shares for all the parties that complained.
     */
    private void readAndVerifyShares(final boolean[] verdicts, final Log log)
        throws ProtocolException {

        log.info("Read open shares.");
        final Log tempLog = log.newChildLog();

        ByteTreeReader reader = null;

        try {

            reader = bullBoard.waitFor(l, "OpenShares", tempLog);

            // If the number of shares is wrong, then we reject.
            if (reader.getRemaining() != k) {
                throw new ProtocolException("Wrong number of shares!");
            }

            // Verify all opened shares.
            for (int i = 1; i <= k; i++) {

                // If the ith party did not complain then we skip the
                // corresponding opening.
                if (verdicts[i]) {

                    skipChild(reader);

                    // If the ith party complained, then we verify that
                    // the opened share is correct.
                } else {

                    readAndVerifyShare(reader, i, tempLog);

                }
            }
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    /**
     * Receives a secret share. Returns true or false depending on if
     * the sharing was accepted or not.
     *
     * @param log Logging context.
     * @return Joint verdict of the sharing.
     */
    public boolean receiveShare(final Log log) {

        logInfoReceive(log, l);

        if (state != State.INITIAL) {
            throw new ProtocolError("Attempting to reuse instance!");
        }

        final Log tempLog = log.newChildLog();

        // Try to read state from file
        if (storeToFile && stateFromFile(tempLog)) {
            return true;
        }

        state = State.ATTEMPTING_RECEIVE;

        boolean allPartiesAccepted = true;
        try {

            // Receive our share and verify that it is correct.
            final boolean ourVerdict = receiveOurShare(tempLog);

            // Exchange verdicts.
            final boolean[] verdicts = exchangeVerdicts(tempLog, ourVerdict);
            allPartiesAccepted = verdicts[0];

            // If somebody complained, then the dealer is given a
            // chance to refute the complaint.
            if (!allPartiesAccepted) {

                readAndVerifyShares(verdicts, tempLog);
            }

        } catch (final ProtocolException pe) {

            tempLog.info(pe.getMessage());
            log.info("Reject sharing of " + ui.getDescrString(l) + ".");

            return false;
        }

        if (!allPartiesAccepted) {
            tempLog.info("Dealer successfully refuted all complaints.");
        }

        tempLog.info("Sharing of " + ui.getDescrString(l) + " is accepted.");
        state = State.SHARE_RECEIVED;

        if (storeToFile) {
            stateToFile(tempLog);
        }

        return true;
    }

    /**
     * Publish our verdict and read the verdicts of all other parties.
     *
     * @param log Logging context.
     * @param verdict Verdict of this party.
     * @return Array of all verdicts, where the boolean at index zero
     * is the conjunction of the verdicts of all parties.
     */
    public boolean[] exchangeVerdicts(final Log log, final boolean verdict) {

        log.info("Exchange verdicts.");
        final Log tempLog = log.newChildLog();

        // Make room for everybody's verdicts.
        final boolean[] verdicts = new boolean[k + 1];
        Arrays.fill(verdicts, true);

        // Store our verdict.
        verdicts[j] = verdict;

        // Exchange verdicts.
        for (int f = 1; f <= k; f++) {

            if (f == j) {

                // Publish our verdict.
                tempLog.info("Publish verdict (" + verdicts[j] + ").");
                bullBoard.publish("Verdict",
                                  ByteTree.booleanToByteTree(verdicts[j]),
                                  tempLog);
            } else {

                // Read verdict of other.
                tempLog.info("Read verdict of " + ui.getDescrString(f) + ".");
                final ByteTreeReader reader =
                    bullBoard.waitFor(f, "Verdict", tempLog);

                // Verdicts that can not be parsed are set to false.
                verdicts[f] = false;
                try {
                    verdicts[f] = reader.readBoolean();
                    tempLog.info("Parse verdict (" + verdicts[f] + ").");
                } catch (final EIOException eioe) {
                    tempLog.info("Unable to parse verdict, setting to false.");
                }
                reader.close();

                // Update conjunction of all verdicts.
                if (!verdicts[f]) {
                    verdicts[0] = false;
                }
            }
        }
        return verdicts;
    }

    /**
     * Sets this instance to be in the trivial state, i.e., it appears
     * as if the dealer correctly dealt a one. This is useful on
     * higher abstraction levels to eliminate the actions of corrupted
     * parties without introducing special handling.
     *
     * @param log Logging context.
     */
    public void setTrivial(final Log log) {
        if (j == l) {
            state = State.SECRET_DISTRIBUTED;
        } else {
            state = State.SHARE_RECEIVED;
        }
        pedersenBasic =
            new PedersenBasic(k,
                              threshold,
                              j,
                              l,
                              pedersenBasic.getHom(),
                              rbitlen);
        trivial = true;

        if (storeToFile) {
            stateToFile(log);
        }
    }

    /**
     * Logs header.
     *
     * @param log Logging context.
     * @param l Index of party or zero to indicate the secret was
     * shared secretly.
     */
    public void logInfoRecover(final Log log, final int l) {
        if (l == 0) {
            log.info("Recover Pedersen VSS generated jointly.");
        } else {
            log.info("Recover Pedersen VSS dealt by " + ui.getDescrString(l)
                     + ".");
        }
    }

    /**
     * Throws an error if an application attempts to re-use an
     * instance.
     */
    private void sanityCheckRecover() {

        if (state != State.SHARE_RECEIVED
            && state != State.SECRET_DISTRIBUTED) {

            final String s = "No valid share has been received (or shared)!";
            throw new ProtocolError(s);
        }
    }

    /**
     * Exchanges secrets between the parties.
     *
     * @param indexes Indexes of valid shares.
     * @param shares Valid shares.
     * @param log Logging context
     */
    private void exchangeSecretShares(final int[] indexes,
                                      final PRingElement[] shares,
                                      final Log log) {

        int noShares = 1;
        for (int i = 1; i <= k; i++) {

            if (i == j) {

                // Publish our share
                log.info("Publish our share.");
                bullBoard.publish("Recover" + l,
                                  pedersenBasic.getShare().toByteTree(),
                                  log);
            } else {

                // Wait for the share of party i.
                log.info("Read share from " + ui.getDescrString(i) + ".");
                final ByteTreeReader reader =
                    bullBoard.waitFor(i, "Recover" + l, log);

                // Parse the share
                indexes[noShares] = i;
                try {
                    shares[noShares] =
                        pedersenBasic.getHom().getDomain().toElement(reader);

                    // Only keep valid shares
                    if (pedersenBasic.verifyShare(i, shares[noShares])) {
                        log.info("Share published by "
                                 + ui.getDescrString(i) + " is correct.");
                        noShares++;
                    } else {
                        log.info("Share published by "
                                 + ui.getDescrString(i) + " is incorrect");
                    }
                } catch (final ArithmFormatException afe) {
                    log.info("Unable to parse share.");
                } finally {
                    reader.close();
                }
            }
        }

        // At this point we should have sufficiently many shares to
        // recover the secret key of party l. If we do not, then
        // something is seriously wrong, and we have to abort.
        if (noShares < threshold) {
            throw new ProtocolError("Insufficient number of honest "
                                    + ui.getDescrString() + "!");
        }
    }


    /**
     * Recovers the secret of the dealer.
     *
     * @param log Logging context.
     * @return Secret of dealer.
     */
    public PRingElement recover(final Log log) {

        // Try to read state from file if needed.
        if (state == State.INITIAL
            && !(storeToFile && stateFromFile(log))) {
            throw new ProtocolError("Unable to read state from file!");
        }

        logInfoRecover(log, l);

        final Log tempLog = log.newChildLog();

        if (secret != null) {

            tempLog.info("Secret has already been recovered.");
            return secret;
        }

        sanityCheckRecover();

        if (trivial) {

            // If the pedersenBasic is trivial, then our share is the
            // secret and there is no need to communicate.
            state = State.SECRET_RECOVERED;
            tempLog.info("Sharing is trivial, returns trivial secret.");

            return pedersenBasic.getShare();
        }

        // Make room for all shares
        final int[] indexes = new int[k];
        final PRingElement[] shares = new PRingElement[k];

        // Initialize with our own share
        indexes[0] = j;
        shares[0] = pedersenBasic.getShare();

        // Get the shares of others

        tempLog.info("Exchange secret shares with all parties.");
        final Log tempLog2 = tempLog.newChildLog();
        exchangeSecretShares(indexes, shares, tempLog2);


        secret = PedersenBasic.recover(indexes, shares, threshold);
        tempLog.info("Interpolate and return secret.");

        state = State.SECRET_RECOVERED;

        return secret;
    }

    /**
     * Returns the first checking element. This is used in distributed
     * key generation for discrete logarithm based primitives.
     *
     * @param log Logging context.
     * @return Constant coefficient in the exponent.
     */
    public PGroupElement getConstCoeffElement(final Log log) {
        if (state == State.SECRET_DISTRIBUTED
            || state == State.SHARE_RECEIVED
            || state == State.SECRET_RECOVERED) {

            return pedersenBasic.getPolynomialInExponent().getElement(0);

        } else {
            throw new ProtocolError("No valid share has been received!");
        }
    }

    // Documented in arithm.PGroupAssociated.java

    @Override
    public PGroup getPGroup() {
        return pedersenBasic.getPGroup();
    }
}
