
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.com.BullBoard;
import com.verificatum.protocol.distr.IndependentGenerators;
import com.verificatum.protocol.distr.IndependentGeneratorsFactory;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.hvzk.CCPoS;
import com.verificatum.protocol.hvzk.CCPoSFactory;
import com.verificatum.protocol.hvzk.PoS;
import com.verificatum.protocol.hvzk.PoSCFactory;
import com.verificatum.protocol.hvzk.PoSFactory;
import com.verificatum.ui.Log;


/**
 * Protocol used to shuffle a list of ciphertexts and prove that it
 * was done correctly using proofs of shuffles, or proofs of shuffles
 * of commitments and then commitment-consistent proofs of
 * shuffles.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions"})
public final class ShufflerElGamalSession extends ProtocolElGamal {

    /**
     * Number of bits in exponent used to squeeze lists into a single
     * list before verifying a commitment-consistent proof of a
     * shuffle.
     */
    public static final int RAISED_BITLENGTH = 50;

    /**
     * Independent generators used to form permutation commitments.
     */
    PGroupElementArray generators;

    /**
     * Reencryption exponents.
     */
    PRingElementArray reencExponents;

    /**
     * Reencryption factors.
     */
    PGroupElementArray reencFactors;

    /**
     * Random exponent used to reduce the complexity of the
     * verification of commitment-consistent proofs of shuffles.
     */
    PRingElement raisedExponent;

    /**
     * Raised independent generators used to verify
     * commitment-consistent proofs of shuffles faster.
     */
    PGroupElementArray raisedGenerators;

    /**
     * Factory for protocol used to generate independent generator.
     */
    IndependentGeneratorsFactory igsFactory;

    /**
     * Factory for creating proofs of shuffles.
     */
    PoSCFactory poscFactory;

    /**
     * Factory for creating commitment-consistent proofs of shuffles.
     */
    CCPoSFactory ccposFactory;

    /**
     * Factory for creating simple proofs of shuffles.
     */
    PoSFactory posFactory;

    /**
     * Subprotocols used to generate verified permutation commitments.
     */
    PermutationCommitment[] permutationCommitments;

    /**
     * Constructs a verifiable decryption protocol.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * com.verificatum.protocol.Protocol#deleteState()} is called.
     */
    protected ShufflerElGamalSession(final String sid,
                                     final ShufflerElGamal prot,
                                     final String rosid,
                                     final File nizkp) {
        super(sid, prot, rosid, nizkp);

        // We set local variables for the factories to allow future
        // versions to set them when instantiating a session.
        this.igsFactory = prot.igsFactory;
        this.poscFactory = prot.poscFactory;
        this.ccposFactory = prot.ccposFactory;
        this.posFactory = prot.posFactory;
    }

    /**
     * Returns the parent shuffler of this session.
     *
     * @return Parent shuffler of this session.
     */
    protected ShufflerElGamal getShuffler() {
        return (ShufflerElGamal) parent;
    }

    @Override
    public void deleteState() {
        super.deleteState();

        if (nizkp != null) {
            ExtIO.delete(nizkp);
        }
    }

    /**
     * Sanity check of order of invocation of methods.
     */
    private void shuffleSanityCheck() {

        // Check that the methods of this session are not called out
        // of order.
        if (readBoolean(".shuffle") || readBoolean(".precomp")) {
            throw new ProtocolError("Attempting to re-use session!");
        } else {
            writeBoolean(".shuffle");
        }
    }

    /**
     * Read output of the given party.
     *
     * @param bullBoard Source of output.
     * @param ciphPPGroup Group to which each ciphertext must belong.
     * @param l Index of producer of the output array of ciphertexts.
     * @param log Logging context.
     * @param input Input array of ciphertexts.
     * @return Output array of ciphertexts.
     */
    private PGroupElementArray readOutput(final BullBoard bullBoard,
                                          final PPGroup ciphPPGroup,
                                          final int l,
                                          final Log log,
                                          final PGroupElementArray input) {

        final ByteTreeReader listReader =
            bullBoard.waitFor(l, "Ciphertext", log);
        try {

            return ciphPPGroup.toElementArray(input.size(), listReader);

        } catch (final ArithmFormatException afe) {

            log.info("Malformed output, replacing with input.");
            return input.copyOfRange(0, input.size());

        } finally {
            listReader.close();
        }
    }

    /**
     * Writes an output array of group elements.
     *
     * @param nizkp Destination of output.
     * @param l Party that computed the output.
     * @param activeThreshold Active threshold.
     * @param output Array of group elements to be written.
     */
    private void writeOutput(final File nizkp,
                             final int l,
                             final int activeThreshold,
                             final PGroupElementArray output) {

        if (nizkp != null && l <= activeThreshold) {

            // Store our output for universal verifiability.
            output.toByteTree().unsafeWriteTo(Lfile(nizkp, l));
        }
    }

    /**
     * Perform the shuffling.
     *
     * @param P Prover.
     * @param ciphPPGroup Group containing ciphertexts.
     * @param ciphertexts Input ciphertexts.
     * @param widePublicKey Widened public key contained in group of
     * ciphertexts.
     * @param permutation Permutation used to shuffle.
     * @param activeThreshold Active threshold.
     * @param log Logging context.
     * @return Shuffled ciphertexts.
     */
    private PGroupElementArray
        performShuffling(final PoS P,
                         final PPGroup ciphPPGroup,
                         final PGroupElementArray ciphertexts,
                         final PGroupElement widePublicKey,
                         final Permutation permutation,
                         final int activeThreshold,
                         final Log log) {

        PGroupElementArray input = ciphertexts;
        PGroupElementArray output = null;

        int validProofs = 0;

        for (int l = 1; l <= activeThreshold; l++) {

            if (l == j) {

                validProofs++;

                // Process input list.
                log.info("Compute output list.");

                final PGroupElementArray reenc = input.mul(reencFactors);
                reencFactors.free();
                reencFactors = null;

                final Permutation inverse = permutation.inv();
                output = reenc.permute(inverse);
                reenc.free();
                inverse.free();

                // Publish our output.
                log.info("Publish output list.");
                bullBoard.publish("Ciphertext",
                                  output.toByteTree(),
                                  log);

                // Prove shuffle.
                P.prove(log,
                        widePublicKey,
                        input,
                        output,
                        reencExponents);

                reencExponents.free();
                reencExponents = null;

                writeOutput(nizkp, l, activeThreshold, output);

            } else if (getActive(l)) {

                // Read the output of Party l.
                log.info("Read output list from " + ui.getDescrString(l) + ".");

                output = readOutput(bullBoard, ciphPPGroup, l, log, input);


                // At this point we are guaranteed to have a correctly
                // formed output list.

                final PoS V =
                    posFactory.newPoS(Integer.toString(l), this, rosid, nizkp);
                V.precompute(log,
                             generators.getPGroup().getg(),
                             generators);

                if (V.verify(log, l, widePublicKey, input, output)) {

                    validProofs++;

                } else {

                    log.info("Replacing output with input.");
                    output.free();
                    output = input.copyOfRange(0, input.size());
                    V.free();
                }

                writeOutput(nizkp, l, activeThreshold, output);
            }

            if (getActive(l)) {

                final PGroupElementArray tmp = input;
                input = output;

                // We do not free the original ciphertexts.
                if (l > 1) {
                    tmp.free();
                }
            }
        }

        if (validProofs < threshold) {
            throw new ProtocolError("Two few proofs are valid, there is "
                                    + "no secure way to proceed! ("
                                    + validProofs + " instead of at least "
                                    + activeThreshold + ")");
        }

        return input;
    }

    /**
     * Shuffle the input ciphertexts and return the result.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be re-encrypted.
     * @return Shuffled output elements.
     */
    public PPGroupElementArray
        shuffle(final Log log,
                final int width,
                final PGroupElementArray ciphertexts) {

        // Check that methods are not called out of order.
        shuffleSanityCheck();

        // Determine ciphertext group and associated exponent ring.
        final PPGroup ciphPPGroup = (PPGroup) ciphertexts.getPGroup();
        final PRing exponentsPRing = ciphPPGroup.project(0).getPRing();

        // We widen the public key to accomodate wider ciphertexts.
        final PGroupElement widePublicKey =
            getWidePublicKey(getShuffler().publicKey, width);

        log.info("Shuffle " + ciphertexts.size() + " ciphertexts.");
        final Log tempLog = log.newChildLog();

        // Generate list of independent generators.
        final IndependentGenerators igs =
            igsFactory.newInstance("generators", this);
        generators = igs.generate(tempLog, pGroup, ciphertexts.size());

        // Generate random permutation and exponents and perform local
        // pre-computation.
        Permutation permutation = null;
        PoS P = null;

        final int activeThreshold = getActiveThreshold();

        if (nizkp != null) {
            ExtIO.unsafeWriteInt(ATfile(nizkp), activeThreshold);
        }

        if (j <= activeThreshold) {

            tempLog.info("Generate reencryption exponents.");
            reencExponents =
                exponentsPRing.randomElementArray(ciphertexts.size(),
                                                  randomSource,
                                                  rbitlen);

            // Compute reencryption factors.
            tempLog.info("Compute reencryption factors.");
            reencFactors = widePublicKey.exp(reencExponents);
            permutation =
                Permutation.random(ciphertexts.size(), randomSource, rbitlen);

            tempLog.info("Perform local pre-computation.");
            P = getShuffler().posFactory.newPoS(Integer.toString(j),
                                                this, rosid, nizkp);
            P.precompute(tempLog,
                         generators.getPGroup().getg(),
                         generators,
                         permutation);
        }

        final PGroupElementArray result = performShuffling(P,
                                                           ciphPPGroup,
                                                           ciphertexts,
                                                           widePublicKey,
                                                           permutation,
                                                           activeThreshold,
                                                           tempLog);
        generators.free();
        if (permutation != null) {
            permutation.free();
        }

        return (PPGroupElementArray) result;
    }

    /**
     * Returns actual width, which is either the input or the width
     * read from file.
     *
     * @param width Actual width, or zero in case the width is stored
     * on file.
     * @return Actual width.
     */
    private int deriveWidth(final int width) {

        // Check that the methods of this session are not called out
        // of order.
        if (readBoolean(".shuffle")) {
            throw new ProtocolError("Attempting to re-use session!");
        } else {
            writeBoolean(".precomp");
        }

        // If we are called to simply read our state, then width may
        // be zero. In this case we read the width used in the
        // previous call.
        int actualWidth = width;
        if (actualWidth == 0) {
            actualWidth = readInt(".width");
        } else {
            writeInt(".width", actualWidth);
        }

        return actualWidth;
    }

    /**
     * Generators raised to a random exponent to optimize online
     * complexity.
     *
     * @param log Logging context.
     * @param pField Underlying field.
     * @param maxciph Maximal number of ciphertexts for which
     * pre-computation is performed.
     */
    private void raisedGenerators(final Log log,
                                  final PField pField,
                                  final int maxciph) {

        ByteTreeReader reader;

        final File raisedGeneratorsFile = getFile("raisedGenerators");
        final File raisedExponentFile = getFile("raisedExponent");

        if (raisedExponentFile.exists()) {

            log.info("Read raised generators.");

            reader = new ByteTreeReaderF(raisedExponentFile);
            raisedExponent = pField.unsafeToElement(reader);
            reader.close();

            reader = new ByteTreeReaderF(raisedGeneratorsFile);
            raisedGenerators = pGroup.unsafeToElementArray(maxciph, reader);
            reader.close();

        } else {

            final LargeInteger exponent =
                new LargeInteger(RAISED_BITLENGTH, randomSource);

            raisedExponent = pField.toElement(exponent);
            raisedExponent.toByteTree().unsafeWriteTo(raisedExponentFile);

            log.info("Compute raised generators.");

            raisedGenerators = generators.exp(raisedExponent);
            raisedGenerators.toByteTree().unsafeWriteTo(raisedGeneratorsFile);

        }
    }

    /**
     * Writes the maximal number of ciphertexts to file.
     *
     * @param actualMaxciph Actual maximal number of ciphertexts that
     * can be shuffled or mixed.
     */
    private void writeMaxciph(final int actualMaxciph) {
        if (nizkp != null && actualMaxciph != 0) {
            ExtIO.unsafeWriteInt(MCfile(nizkp), actualMaxciph);
        }
    }

    /**
     * Protocol where the first {@link #threshold} active parties
     * pre-compute values, and commit to permutations and prove that
     * they can open them correctly.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param maxciph Number of ciphertexts for which pre-computation is
     * performed.
     */
    protected void precomp(final Log log, final int width, final int maxciph) {

        final int actualWidth = deriveWidth(width);
        int actualMaxciph = maxciph;

        // Write maxciph to proof directory to make it self-contained.
        writeMaxciph(actualMaxciph);

        log.info("Perform pre-computation for " + actualMaxciph + " senders.");
        final Log tempLog = log.newChildLog();

        ByteTreeReader reader;

        // Generate list of independent generators.
        final File generatorsFile = getFile("generators");

        if (generatorsFile.exists()) {

            // Read reencryption exponents from file.
            tempLog.info("Read generators.");
            reader = new ByteTreeReaderF(generatorsFile);
            generators = pGroup.unsafeToElementArray(actualMaxciph, reader);
            reader.close();

            // This is a little magical. If actualMaxciph == 0, then reading is
            // done for an arbitrary actualMaxciph, but we may need the actual
            // actualMaxciph below, so let's set it.
            actualMaxciph = generators.size();

        } else {

            // Generate independent generators.
            final IndependentGenerators igs =
                igsFactory.newInstance("generators", this);
            generators = igs.generate(tempLog, pGroup, actualMaxciph);

            tempLog.info("Write generators to file.");
            generators.toByteTree().unsafeWriteTo(generatorsFile);
        }

        // Determine ciphertext group and associated exponent ring.
        final PPGroup ciphPPGroup = getCiphPGroup(pGroup, actualWidth);
        final PRing exponentsPRing = ciphPPGroup.project(0).getPRing();

        // We widen the public key to accomodate wider ciphertexts.
        final PGroupElement widePublicKey =
            getWidePublicKey(getShuffler().publicKey, actualWidth);

        // The following is used to reduce the complexity of the
        // verification of commitment-consistent proofs of shuffle by
        // a factor of roughly 2/3.

        final PField pField = pGroup.getPRing().getPField();

        raisedGenerators(tempLog, pField, actualMaxciph);

        final int activeThreshold = getActiveThreshold();

        if (nizkp != null) {
            ExtIO.unsafeWriteInt(ATfile(nizkp), activeThreshold);
        }

        // Generate permutation commitments.
        permutationCommitments = new PermutationCommitment[activeThreshold + 1];
        for (int l = 1; l <= activeThreshold; l++) {

            permutationCommitments[l] =
                new PermutationCommitment(Integer.toString(l),
                                          this,
                                          rosid,
                                          nizkp,
                                          l,
                                          generators,
                                          poscFactory);
        }

        // Perform pre-computation in a parallel thread.
        if (j <= activeThreshold) {
            permutationCommitments[j].precompute(tempLog);
        }

        for (int l = 1; l <= activeThreshold; l++) {

            if (getActive(l)) {
                permutationCommitments[l].generate(tempLog, raisedExponent);
            }
        }

        if (j <= activeThreshold) {

            final File reencExponentsFile = getFile("reencExponents");
            final File reencFactorsFile = getFile("reencFactors");

            if (reencExponentsFile.exists()) {

                // Read reencryption exponents from file.
                tempLog.info("Read reencryption exponents.");
                reader = new ByteTreeReaderF(reencExponentsFile);
                reencExponents =
                    exponentsPRing.unsafeToElementArray(actualMaxciph, reader);
                reader.close();

                // Read reencryption factors from file.
                tempLog.info("Read reencryption factors.");
                reader = new ByteTreeReaderF(reencFactorsFile);
                reencFactors =
                    ciphPPGroup.unsafeToElementArray(actualMaxciph, reader);
                reader.close();

            } else {

                // Generate random exponents.
                tempLog.info("Generate reencryption exponents.");
                reencExponents =
                    exponentsPRing.randomElementArray(actualMaxciph,
                                                      randomSource,
                                                      rbitlen);

                tempLog.info("Write reencryption exponents to file.");
                reencExponents.toByteTree().unsafeWriteTo(reencExponentsFile);

                // Construct the group element input from the public key
                // and an array of ones.
                tempLog.info("Compute reencryption factors.");
                reencFactors = widePublicKey.exp(reencExponents);

                tempLog.info("Write reencryption factors to file.");
                reencFactors.toByteTree().unsafeWriteTo(reencFactorsFile);
            }
        }
    }

    /**
     * Shrinks generators, reencryption exponents and factors, as well
     * as commitments to the actual number of ciphertexts.
     *
     * @param log Logging context.
     * @param noCiphertexts Actual number of ciphertexts.
     */
    private void shrink(final Log log, final int noCiphertexts) {

        final int activeThreshold = getActiveThreshold();

        log.info("Shrink pre-computed values to " + noCiphertexts
                 + " ciphertexts.");
        final Log tempLog = log.newChildLog();

        // Shrink independent generators.
        tempLog.info("Shrink number of generators.");
        final PGroupElementArray oldGenerators = generators;
        generators = generators.copyOfRange(0, noCiphertexts);
        oldGenerators.free();

        tempLog.info("Shrink number of raised generators.");
        final PGroupElementArray oldRaisedGenerators = raisedGenerators;
        raisedGenerators = raisedGenerators.copyOfRange(0, noCiphertexts);
        oldRaisedGenerators.free();

        if (j <= activeThreshold) {

            // Shrink reencryption exponents and factors.
            tempLog.info("Shrink reencryption exponents.");
            final PRingElementArray oldReencExponents = reencExponents;
            reencExponents = reencExponents.copyOfRange(0, noCiphertexts);
            oldReencExponents.free();

            tempLog.info("Shrink reencryption factors.");
            final PGroupElementArray oldReencFactors = reencFactors;
            reencFactors = reencFactors.copyOfRange(0, noCiphertexts);
            oldReencFactors.free();
        }

        // Shrink permutation commitments.
        for (int l = 1; l <= activeThreshold; l++) {
            if (getActive(l)) {
                permutationCommitments[l].shrink(tempLog, noCiphertexts);
            }
        }
    }

    /**
     * Sanity check of attempt to shuffle a commitment.
     */
    void sanityCheckCommittedShuffle() {

        // Check that the methods of this session are not called out
        // of order.
        if (readBoolean(".precomp")) {
            writeBoolean(".precomp");
        } else {
            final String e =
                "Attempting to use commitment-consistent proofs of "
                + "shuffles without first committing!";
            throw new ProtocolError(e);
        }
    }

    /**
     * Return next valid array.
     *
     * @param l Index of array.
     * @param input Input array.
     * @param output Next relevant array.
     * @return Next valid array.
     */
    private PGroupElementArray
        newInputFreeOld(final int l,
                        final PGroupElementArray input,
                        final PGroupElementArray output) {
        if (getActive(l)) {

            // We free anything except the original input.
            if (l > 1) {
                input.free();
            }
            return output;

        } else {

            return input;
        }
    }

    /**
     * Performs a shuffling of a commitment and uses precomputed
     * values if available.
     *
     * @param l Index of current party.
     * @param widePublicKey Public key widened to fit the ciphertext
     * group.
     * @param input Input array of ciphertexts.
     * @param nextOutput Output array of ciphertexts if precomputed.
     * @param nizkp Destination directory.
     * @param activeThreshold Largest index of an active party.
     * @param log Logging context.
     * @return Output array of ciphertexts.
     */
    private PGroupElementArray
        committedShuffleShuffle(final int l,
                                final PGroupElement widePublicKey,
                                final PGroupElementArray input,
                                final PGroupElementArray[] nextOutput,
                                final File nizkp,
                                final int activeThreshold,
                                final Log log) {

        PGroupElementArray output = null;

        // Process input list.
        final Permutation permutation =
            permutationCommitments[j].getPermutation();

        if (nextOutput[0] == null) {

            log.info("Re-encrypt input list.");
            final PGroupElementArray reenc = input.mul(reencFactors);

            log.info("Permute re-encrypted list.");
            output = reenc.permute(permutation.inv());
            reenc.free();

        } else {

            // If we have already optimistically computed our output,
            // we simply use it.
            output = nextOutput[0];
            nextOutput[0] = null;
        }

        // Publish our output.
        log.info("Publish output list.");
        bullBoard.publish("Ciphertext", output.toByteTree(), log);

        // Prove correctness of our output.
        final CCPoS P =
            ccposFactory.newPoS(Integer.toString(j), this, rosid, nizkp);
        P.prove(log,
                generators.getPGroup().getg(),
                generators,
                permutationCommitments[j].getCommitment(),
                widePublicKey,
                input,
                output,
                permutationCommitments[j].getExponents(),
                permutation,
                reencExponents);

        if (nizkp != null && l < activeThreshold) {

            // Store our output for universal verifiability.
            output.toByteTree().unsafeWriteTo(Lfile(nizkp, j));
        }

        return output;
    }

    /**
     * Optimized committed shuffle.
     *
     * @param output Output ciphertexts.
     * @param reencFactors Reencryption factors.
     * @param permComm Permutation commitments.
     * @param nextOutput If not null, then the output plaintexts.
     * @return Thread computing the verification.
     */
    private Thread
        committedShuffleVerifyOptim(final PGroupElementArray output,
                                    final PGroupElementArray reencFactors,
                                    final PermutationCommitment permComm,
                                    final PGroupElementArray[] nextOutput) {

        final PGroupElementArray myInput = output;

        final Thread nextOutputThread = new Thread() {
                @Override
                public void run() {
                    final PGroupElementArray reenc = myInput.mul(reencFactors);
                    final Permutation permutation = permComm.getPermutation();
                    nextOutput[0] = reenc.permute(permutation.inv());
                    reenc.free();
                }
            };
        nextOutputThread.start();

        return nextOutputThread;
    }

    /**
     * Perform committed shuffle.
     *
     * @param l Index of current party.
     * @param ciphPPGroup Group containing ciphertexts.
     * @param widePublicKey Public key widened to fit the ciphertext
     * group.
     * @param input Input array of ciphertexts.
     * @param nextOutput Output array of ciphertexts if precomputed.
     * @param nizkp Destination directory.
     * @param activeThreshold Largest index of an active party.
     * @param log Logging contexts.
     * @return Shuffled ciphertexts.
     */
    private PGroupElementArray
        committedShuffleVerify(final int l,
                               final PPGroup ciphPPGroup,
                               final PGroupElement widePublicKey,
                               final PGroupElementArray input,
                               final PGroupElementArray[] nextOutput,
                               final File nizkp,
                               final int activeThreshold,
                               final Log log) {

        PGroupElementArray output = null;

        // Read the output of Party l.
        log.info("Read output list from " + ui.getDescrString(l) + ".");

        output = readOutput(bullBoard, ciphPPGroup, l, log, input);

        // If we are next, then we compute our output optimistically
        // in parallel with verification.
        Thread nextOutputThread = null;
        if (l + 1 <= activeThreshold && l + 1 == j) {
            nextOutputThread =
                committedShuffleVerifyOptim(output,
                                            reencFactors,
                                            permutationCommitments[j],
                                            nextOutput);
        }

        // We assume that the output is correct, which means that our
        // optimistically compute output will be useful.
        boolean correct = true;

        // Verify proof of correctness of Party l
        final CCPoS V =
            ccposFactory.newPoS(Integer.toString(l), this, rosid, nizkp);
        if (!V.verify(log,
                      l,
                      generators.getPGroup().getg(),
                      generators,
                      permutationCommitments[l].
                      getCommitment(),
                      widePublicKey,
                      input,
                      output,
                      permutationCommitments[l].
                      getRaisedCommitment(),
                      raisedGenerators,
                      raisedExponent)) {

            // If the proof fails, then we replace the output by the
            // output.
            log.info("Replace output by the input.");
            output.free();
            output = input.copyOfRange(0, input.size());

            // We need to drop the optimistically computed
            // output, since it is based on wrong input.
            correct = false;
        }

        // We wait for the optimistic pre-computation of our output to
        // complete if we are performing such a computation.
        if (nextOutputThread != null) {
            try {
                nextOutputThread.join();
            } catch (final InterruptedException ie) {
                throw new ProtocolError("Unable to join threads!", ie);
            }
            nextOutputThread = null;
        }

        // If the proof was rejected, then we need to drop our
        // optimistically computed output.
        if (!correct && nextOutput[0] != null) {
            nextOutput[0].free();
            nextOutput[0] = null;
        }

        if (nizkp != null && l < activeThreshold) {

            // Store the output for universal verifiability.
            output.toByteTree().unsafeWriteTo(Lfile(nizkp, l));
        }
        return output;
    }


    /**
     * Perform re-encryption of the input list of ciphertexs relative
     * to permutation commitments. {@link #precomp(Log,int,int)} must
     * be called before this method.
     *
     * @param log Logging context.
     * @param width Width of ciphertexts.
     * @param ciphertexts Ciphertexts to be decrypted
     * @return Committed shuffle.
     */
    public PPGroupElementArray
        committedShuffle(final Log log,
                         final int width,
                         final PGroupElementArray ciphertexts) {

        final int activeThreshold = getActiveThreshold();

        sanityCheckCommittedShuffle();

        // Fetch pre-computed data.
        precomp(log, 0, 0);

        // Determine ciphertext group and associated exponent ring.
        final PPGroup ciphPPGroup = (PPGroup) ciphertexts.getPGroup();

        // We widen the public key to accomodate wider ciphertexts.
        final PGroupElement widePublicKey =
            getWidePublicKey(getShuffler().publicKey, width);

        log.info("Shuffle " + ciphertexts.size() + " ciphertexts.");
        final Log tempLog = log.newChildLog();

        // Shrink the pre-computed values and the commitments to the
        // actal number of ciphertexts to be processed.
        shrink(log, ciphertexts.size());

        // The following code is written in this convoluted way to
        // improve parallelism.

        PGroupElementArray input = ciphertexts;
        PGroupElementArray output = null;

        final PGroupElementArray[] nextOutput = new PGroupElementArray[1];

        nextOutput[0] = null;

        for (int l = 1; l <= activeThreshold; l++) {

            if (l == j) {

                output = committedShuffleShuffle(l,
                                                 widePublicKey,
                                                 input,
                                                 nextOutput,
                                                 nizkp,
                                                 activeThreshold,
                                                 tempLog);

            } else if (getActive(l)) {

                output = committedShuffleVerify(l,
                                                ciphPPGroup,
                                                widePublicKey,
                                                input,
                                                nextOutput,
                                                nizkp,
                                                activeThreshold,
                                                tempLog);
            }

            input = newInputFreeOld(l, input, output);
        }

        free();

        return (PPGroupElementArray) input;
    }

    /**
     * Release the resources allocated by this instance.
     */
    protected void free() {

        final int activeThreshold = getActiveThreshold();

        if (permutationCommitments != null) {
            for (int l = 1; l <= activeThreshold; l++) {
                if (permutationCommitments[l] != null) {
                    permutationCommitments[l].free();
                }
            }
        }
        if (j <= activeThreshold) {
            if (reencExponents != null) {
                reencExponents.free();
            }
            if (reencFactors != null) {
                reencFactors.free();
            }
        }
        if (generators != null) {
            generators.free();
        }
        if (raisedGenerators != null) {
            raisedGenerators.free();
        }
    }

    /**
     * Name of file containing an intermediate list of ciphertexts.
     *
     * @param nizkp Destination directory of list of ciphertexts.
     * @param index Index of mix-server.
     * @return File where intermediate file is stored.
     */
    public static File Lfile(final File nizkp, final int index) {
        return new File(nizkp, String.format("Ciphertexts%02d.bt", index));
    }

    /**
     * Name of file containing the number of ciphertexts for which
     * pre-computing is performed.
     *
     * @param nizkp Destination directory of list of ciphertexts.
     * @return File containing number of ciphertexts for which
     * pre-computation is performed.
     */
    public static File MCfile(final File nizkp) {
        return new File(nizkp, "maxciph");
    }

    /**
     * Name of file containing the threshold of active mix-servers.
     *
     * @param nizkp Destination directory.
     * @return File containing threshold of active mix-servers.
     */
    public static File ATfile(final File nizkp) {
        return new File(nizkp, "activethreshold");
    }
}
