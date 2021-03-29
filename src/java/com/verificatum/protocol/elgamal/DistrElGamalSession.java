
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

import com.verificatum.arithm.ArithmException;
import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.arithm.PRingElement;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.distr.DKG;
import com.verificatum.protocol.mixnet.ShufflerElGamalSession;
import com.verificatum.ui.Log;


/**
 * Implements a verifiable decryption protocol for the El Gamal
 * cryptosystem with optimistic verification of combined proof. If the
 * optimistic verification fails, then proofs are verified separately,
 * the needed keys recovered, and decryption factors for these keys
 * are computed in the open.
 *
 * @author Douglas Wikstrom
 */
public final class DistrElGamalSession extends ProtocolElGamal {

    /**
     * Distributed keys.
     */
    DKG dkg;

    /**
     * Constructs a verifiable decryption protocol.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs.
     */
    protected DistrElGamalSession(final String sid,
                                  final DistrElGamal prot,
                                  final String rosid,
                                  final File nizkp) {
        super(sid, prot, rosid, nizkp);
        this.dkg = prot.dkg;
    }

    @Override
    public void deleteState() {
        super.deleteState();

        if (nizkp != null) {
            ExtIO.delete(nizkp);
        }
    }

    /**
     * Returns the parent of this session.
     *
     * @return Parent of this session.
     */
    protected DistrElGamal getDistr() {
        return (DistrElGamal) parent;
    }


    /**
     * Exchange decryption factors.
     *
     * @param leftPGroup Left side of the ciphertext group.
     * @param decryptionFactors Decryption factors of all parties.
     * @param correct Array of verdicts.
     * @param nizkp Destination directory.
     * @param log Logging context.
     */
    private void
        exchangeDecryptionFactors(final PGroup leftPGroup,
                                  final PGroupElementArray[] decryptionFactors,
                                  final boolean[] correct,
                                  final File nizkp,
                                  final Log log) {

        // Publish our decryption factors and collect decryption
        // factors of everybody else.
        log.info("Collect decryption factors.");
        final Log tempLog = log.newChildLog();

        final int size = decryptionFactors[j].size();

        for (int l = 1; l <= k; l++) {

            if (l == j) {

                // Publish our decryption factors.
                tempLog.info("Publish decryption factors.");
                bullBoard.publish("DecryptionFactors",
                                  decryptionFactors[j].toByteTree(),
                                  tempLog);
            } else {

                if (getActive(l)) {

                    // Read and set the commitment of other party.
                    tempLog.info("Read decryption factors of "
                                 + ui.getDescrString(l) + ".");
                    final ByteTreeReader factorsReader =
                        bullBoard.waitFor(l, "DecryptionFactors", tempLog);

                    try {

                        decryptionFactors[l] =
                            leftPGroup.toElementArray(size, factorsReader);

                    } catch (final ArithmFormatException afe) {

                        tempLog.info("Reading failed, setting to all-one "
                                     + "array.");

                        // We know already now that these decryption
                        // factors are not correct.
                        correct[l] = false;

                    } finally {
                        factorsReader.close();
                    }

                } else {

                    tempLog.info("Not active, setting to all-one array.");
                    correct[l] = false;

                }

            }
            if (!correct[l]) {

                // If the decryption factors could not be parsed we
                // set them all to one.
                decryptionFactors[l] =
                    leftPGroup.toElementArray(size, leftPGroup.getONE());
            }

            // Export decryption factors. Note that we export the
            // all-one array if somebody publishes malformed
            // decryption factors.
            if (nizkp != null) {
                decryptionFactors[l].toByteTree().
                    unsafeWriteTo(DFfile(nizkp, l));
            }
        }
    }

    /**
     * Exchange commitments.
     *
     * @param basic Basic functionality for distributed decryption.
     * @param correct Array of verdicts.
     * @param nizkp Destination directory.
     * @param log Logging context.
     */
    private void exchangeCommitments(final DistrElGamalSessionBasic basic,
                                     final boolean[] correct,
                                     final File nizkp,
                                     final Log log) {

        log.info("Collect commitments.");
        final Log tempLog = log.newChildLog();
        for (int l = 1; l <= k; l++) {

            if (l == j) {

                tempLog.info("Publish commitment.");
                final ByteTreeBasic commitment = basic.commit(randomSource);
                bullBoard.publish("Commitment", commitment, tempLog);

                // Export proof commitment.
                if (nizkp != null) {
                    commitment.unsafeWriteTo(DFCfile(nizkp, j));
                }

            } else {

                tempLog.info("Read commitment of " + ui.getDescrString(l)
                             + ".");
                final ByteTreeReader commitmentReader =
                    bullBoard.waitFor(l, "Commitment", tempLog);
                try {

                    basic.setCommitment(l, commitmentReader);
                    if (!basic.getVerdict(l)) {
                        tempLog.info("Failed, setting to one-array.");
                        correct[l] = false;
                    }

                    // Export proof commitment.
                    if (nizkp != null) {
                        basic.getCommitment(l).
                            unsafeWriteTo(DFCfile(nizkp, l));
                    }

                } finally {
                    commitmentReader.close();
                }
            }
        }
    }

    /**
     * Exchange replies.
     *
     * @param basic Basic functionality for distributed decryption.
     * @param integerChallenge Challenge value.
     * @param correct Array of verdicts.
     * @param nizkp Destination directory.
     * @param log Logging context.
     */
    private void exchangeReplies(final DistrElGamalSessionBasic basic,
                                 final LargeInteger integerChallenge,
                                 final boolean[] correct,
                                 final File nizkp,
                                 final Log log) {

        log.info("Collect replies.");
        final Log tempLog = log.newChildLog();
        for (int l = 1; l <= k; l++) {

            if (l == j) {

                tempLog.info("Publish reply.");
                final ByteTreeBasic reply = basic.reply(integerChallenge);
                bullBoard.publish("Reply", reply, tempLog);

                // Export proof reply.
                if (nizkp != null) {
                    reply.unsafeWriteTo(DFRfile(nizkp, j));
                }

            } else {

                tempLog.info("Read reply of " + ui.getDescrString(l) + ".");
                final ByteTreeReader replyReader =
                    bullBoard.waitFor(l, "Reply", tempLog);
                try {

                    basic.setReply(l, replyReader);
                    if (!basic.getVerdict(l)) {
                        tempLog.info("Failed, setting to zero reply.");
                        correct[l] = false;
                    }

                } finally {
                    replyReader.close();
                }

                // Export proof reply.
                if (nizkp != null) {
                    basic.getReply(l).unsafeWriteTo(DFRfile(nizkp, l));
                }
            }
        }
    }

    /**
     * Verify proofs separately.
     *
     * @param basic Basic functionality for distributed decryption.
     * @param integerChallenge Challenge value.
     * @param correct Array of verdicts.
     * @param log Logging context.
     */
    private void verifySeparately(final DistrElGamalSessionBasic basic,
                                  final LargeInteger integerChallenge,
                                  final boolean[] correct,
                                  final Log log) {

        log.info("Verify proofs for decryption factors separately.");
        final Log tempLog = log.newChildLog();

        for (int l = 1; l <= k; l++) {

            if (correct[l] && l != j) {

                tempLog.info("Verify proof of " + ui.getDescrString(l) + ".");
                final Log tempLog2 = tempLog.newChildLog();

                tempLog2.info("Batch decryption factors.");
                basic.batch(l);

                tempLog2.info("Perform verification.");
                correct[l] = basic.verify(l, integerChallenge);

                if (correct[l]) {
                    tempLog2.info("Accepted proof.");
                } else {
                    tempLog2.info("Rejected proof.");
                }
            }
        }
    }

    /**
     * Performs the joint verifiable decryption.
     *
     * @param log Logging context.
     * @param ciphertexts Ciphertexts to decrypt.
     * @return Array of plaintexts.
     */
    public PGroupElementArray decrypt(final Log log,
                                      final PGroupElementArray ciphertexts) {

        if (nizkp != null) {
            ExtIO.unsafeWriteInt(ShufflerElGamalSession.ATfile(nizkp),
                                 getActiveThreshold());
        }

        final PField pField = ciphertexts.getPGroup().getPRing().getPField();

        // Indices of valid decryption factors.
        final boolean[] correct = new boolean[k + 1];
        Arrays.fill(correct, true);

        log.info("Decrypt " + ciphertexts.size() + " ciphertexts.");
        final Log tempLog = log.newChildLog();

        // Compute our own decryption factors. Here we use the product
        // of our secret share and the inverse factor defined above to
        // speed up combination of decryption factors.
        tempLog.info("Compute decryption factors.");
        PRingElement inverseFactor;
        try {

            inverseFactor = DistrElGamalSessionBasic.prodFactor(pField, k);
            inverseFactor = inverseFactor.inv();

        } catch (final ArithmException ae) {
            throw new ProtocolError("This should never happen!", ae);
        }

        // Extract first components of all ciphertexts and their
        // underlying group.
        final PGroupElementArray firstComponents =
            ((PPGroupElementArray) ciphertexts).project(0);

        // Make room for all decryption factors.
        PGroupElementArray[] decryptionFactors =
            new PGroupElementArray[k + 1];

        decryptionFactors[j] =
            firstComponents.exp(dkg.getSecretKey().neg().mul(inverseFactor));

        // Export our own decryption factors.
        if (nizkp != null) {
            decryptionFactors[j].toByteTree().unsafeWriteTo(DFfile(nizkp, j));
        }

        final PGroup leftPGroup = firstComponents.getPGroup();

        // Exchange the decryption factors.
        exchangeDecryptionFactors(leftPGroup,
                                  decryptionFactors,
                                  correct,
                                  nizkp,
                                  tempLog);


        // Optimistically compute the combined decryption factors of
        // the first threshold number of decryption factors that a
        // least were correctly formatted.

        PGroupElementArray combDecryptionFactors =
            DistrElGamalSessionBasic.combineDecryptionFactors(decryptionFactors,
                                                              correct,
                                                              k,
                                                              threshold);

        // Create underlying Sigma prover/verifier.
        final DistrElGamalSessionBasic basic =
            new DistrElGamalSessionBasic(j,
                                         k,
                                         threshold,
                                         ebitlen(),
                                         rbitlen,
                                         prg);

        // Initialize the instance.
        basic.setInstance(dkg.getBasicPublicKey(),
                          firstComponents,
                          dkg.getPublicKeys(),
                          decryptionFactors,
                          dkg.getSecretKey(),
                          dkg.getJointPublicKey(),
                          combDecryptionFactors);


        // Note that in the following we include the values of all
        // parties and not only the ones we later use.

        // Build byte tree of all inputs.
        final ByteTreeBasic btIn =
            new ByteTreeContainer(dkg.getBasicPublicKey().toByteTree(),
                                  ciphertexts.toByteTree());

        // Turn public keys into a byte tree.
        final ByteTreeBasic pkBT = dkg.getPolynomialInExponent().toByteTree();

        // Turn decryption factors into a byte tree.
        final ByteTreeBasic[] decryptionFactorsBT = new ByteTreeBasic[k];
        for (int i = 0; i < k; i++) {
            decryptionFactorsBT[i] = decryptionFactors[i + 1].toByteTree();
        }
        final ByteTreeBasic dfBT = new ByteTreeContainer(decryptionFactorsBT);

        // Build byte tree of all outputs.
        final ByteTreeBasic btOut = new ByteTreeContainer(pkBT, dfBT);

        // Build input to challenger.
        final ByteTreeBasic seedData = new ByteTreeContainer(btIn, btOut);

        // Generate a seed.
        tempLog.info("Generate seed for batching.");
        Log tempLog2 = tempLog.newChildLog();
        final byte[] prgSeed = challenger.challenge(tempLog2,
                                                    seedData,
                                                    8 * prg.minNoSeedBytes(),
                                                    rbitlen);
        basic.setBatchVector(prgSeed);

        // Batch the input.
        tempLog.info("Batch input ciphertexts.");
        basic.batchInput();

        // Collect commitments.
        exchangeCommitments(basic, correct, nizkp, tempLog);

        // Generate a challenge
        tempLog.info("Generate challenge.");
        tempLog2 = tempLog.newChildLog();
        final ByteTreeBasic challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), basic.getCommitment());

        final byte[] challengeBytes =
            challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        // Collect replies.
        exchangeReplies(basic, integerChallenge, correct, nizkp, log);

        // Try to verify a combined proof for the first threshold
        // parties for which we don't already know submitted faulty
        // data.
        tempLog.info("Verify a combined proof.");
        tempLog2 = tempLog.newChildLog();

        tempLog2.info("Combine proof commitments and replies.");
        basic.combine(correct);

        tempLog2.info("Batch combined decryption factors.");
        basic.batchCombined();

        tempLog2.info("Perform verification.");
        boolean verdict = basic.verifyCombined(integerChallenge);

        if (verdict) {
            tempLog2.info("Accepted joint proof.");
        } else {
            tempLog2.info("Rejected joint proof.");
            combDecryptionFactors.free();
            combDecryptionFactors = null;
            verdict = false;
        }

        // If anything went wrong with the parsing or if the joint
        // verification failed, then we verify the decryption factors
        // of different parties separately.
        if (!verdict) {
            verifySeparately(basic, integerChallenge, correct, tempLog);
        }
        basic.free();


        // Compute plaintexts.
        if (combDecryptionFactors == null) {

            tempLog.info("Combine correct decryption factors.");
            combDecryptionFactors =
                DistrElGamalSessionBasic.
                combineDecryptionFactors(decryptionFactors,
                                         correct,
                                         k,
                                         threshold);

        }

        for (int l = 1; l <= k; l++) {
            decryptionFactors[l].free();
        }

        tempLog.info("Compute plaintexts.");
        final PGroupElementArray plaintexts =
            ((PPGroupElementArray) ciphertexts)
            .project(1).mul(combDecryptionFactors);
        combDecryptionFactors.free();

        // Store the array indicating the indices of correct shares.
        ByteTree.booleanArrayToByteTree(correct).unsafeWriteTo(CRfile(nizkp));

        return plaintexts;
    }

    /**
     * Name of file containing the indices of correct shares.
     *
     * @param nizkp Destination directory.
     * @return File name of file containing correct indices.
     */
    public static File CRfile(final File nizkp) { // NOPMD
        return new File(nizkp, "CorrectIndices.bt");
    }

    /**
     * Name of file containing the input list of ciphertexts.
     *
     * @param nizkp Destination directory.
     * @return File name of file containing ciphertexts.
     */
    public static File Cfile(final File nizkp) { // NOPMD
        return new File(nizkp, "Ciphertexts");
    }

    /**
     * Name of file containing decryption factors.
     *
     * @param index index of party.
     * @param nizkp Destination directory.
     * @return File where decryption factors are stored.
     */
    public static File DFfile(final File nizkp, final int index) { // NOPMD
        return new File(nizkp,
                        String.format("DecryptionFactors%02d.bt", index));
    }

    /**
     * Name of file containing the commitment of a proof.
     *
     * @param index index of party.
     * @param nizkp Destination directory.
     * @return File where the secret key is stored.
     */
    public static File DFCfile(final File nizkp, final int index) { // NOPMD
        return new File(nizkp,
                        String.format("DecrFactCommitment%02d.bt", index));
    }

    /**
     * Name of file containing the reply of a proof.
     *
     * @param index index of party.
     * @param nizkp Destination directory.
     * @return File where the secret key is stored.
     */
    public static File DFRfile(final File nizkp, final int index) { // NOPMD
        return new File(nizkp,
                        String.format("DecrFactReply%02d.bt", index));
    }
}
