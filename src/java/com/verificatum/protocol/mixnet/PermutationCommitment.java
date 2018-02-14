
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
import java.util.Arrays;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.hvzk.PoSC;
import com.verificatum.protocol.hvzk.PoSCFactory;
import com.verificatum.protocol.hvzk.PoSTW;
import com.verificatum.ui.Log;


/**
 * Generates permutation commitments such that receivers are convinced
 * that the committer can open its commitment to a correct permutation
 * commitment.
 *
 * @author Douglas Wikstrom
 */
public final class PermutationCommitment extends ProtocolElGamal {

    /**
     * Index of committer.
     */
    int l;

    /**
     * Independent generators.
     */
    PGroupElementArray generators;

    /**
     * Factory for the proof of a shuffle used.
     */
    PoSCFactory poscFactory;

    /**
     * Committed permutation.
     */
    Permutation permutation;

    /**
     * Commitment exponents.
     */
    PRingElementArray exponents;

    /**
     * Permutation commitment.
     */
    PGroupElementArray commitment;

    /**
     * Raised permutation commitment used to speed up the verification
     * of a commitment-consistent proof of a shuffle.
     */
    PGroupElementArray raisedCommitment;

    /**
     * Commitment of the identity permutation.
     */
    PGroupElementArray identityCommitment;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Underlying proof of a shuffle.
     */
    PoSC posc;

    /**
     * Indicates that precomputation phase read data from file.
     */
    boolean fromFile;

    /**
     * Creates a correct permutation commitment with the given
     * committer.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * com.verificatum.protocol.Protocol#deleteState()} is called.
     * @param l Index of committer.
     * @param generators Independent generators used to commit to a
     * permutation.
     * @param poscFactory Factory for proofs of shuffles.
     */
    public PermutationCommitment(final String sid,
                                 final ProtocolElGamal protocol,
                                 final String rosid,
                                 final File nizkp,
                                 final int l,
                                 final PGroupElementArray generators,
                                 final PoSCFactory poscFactory) {
        super(sid, protocol, rosid, nizkp);
        this.l = l;
        this.generators = generators;
        this.pGroup = generators.getPGroup();
        this.poscFactory = poscFactory;
    }

    /**
     * Precompute as much as possible of the generation.
     *
     * @param log Logging context.
     */
    public void precompute(final Log log) {

        final int size = generators.size();
        ByteTreeReader reader;

        log.info("Pre-compute permutation commitment.");
        final Log tempLog = log.newChildLog();

        final File permFile = getFile("Permutation");
        final File commExpFile = getFile("Exponents");
        final File idCommFile = getFile("IdentityCommitment");

        if (permFile.exists()) {

            // Read permutation
            tempLog.info("Read permutation from file.");
            reader = new ByteTreeReaderF(permFile);

            permutation = Permutation.unsafeToPermutation(size, reader);
            reader.close();

            // Read identity commitment.
            tempLog.info("Read identity commitment from file.");
            reader = new ByteTreeReaderF(idCommFile);
            identityCommitment = pGroup.unsafeToElementArray(size, reader);
            reader.close();

            // Compute permutation commitment.
            tempLog.info("Permute identity commitment.");
            commitment = identityCommitment.permute(permutation);

            // Read commitment exponents
            tempLog.info("Read commitment exponents from file.");
            reader = new ByteTreeReaderF(commExpFile);
            exponents = pGroup.getPRing().unsafeToElementArray(size, reader);
            reader.close();

            fromFile = true;

        } else {

            // Generate commitment exponents.
            tempLog.info("Generate commitment exponents.");
            exponents = pGroup.getPRing().randomElementArray(size,
                                                             randomSource,
                                                             rbitlen);

            tempLog.info("Write commitment exponents to file.");
            exponents.toByteTree().unsafeWriteTo(commExpFile);

            // Compute identity commitment.
            tempLog.info("Compute identity commitment.");
            final PGroupElementArray tmp = pGroup.getg().exp(exponents);
            identityCommitment = generators.mul(tmp);
            tmp.free();

            tempLog.info("Write identity commitment to file.");
            identityCommitment.toByteTree().unsafeWriteTo(idCommFile);

            // Generate permutation.
            tempLog.info("Generate random permutation.");
            permutation = Permutation.random(size, randomSource, rbitlen);

            tempLog.info("Write permutation to file.");
            permutation.toByteTree().unsafeWriteTo(permFile);

            // Permute identity commitment.
            commitment = identityCommitment.permute(permutation);

            fromFile = false;
        }
    }

    /**
     * Name of file containing permutation commitment.
     *
     * @param nizkp Proof directory.
     * @param index index of mix-server.
     * @return File where permutation commitments are stored.
     */
    protected static File PCfile(final File nizkp, final int index) { // NOPMD
        return PoSTW.PCfile(nizkp, index);
    }

    /**
     * Name of file containing list used to shrink precomputed values
     * to the actual size.
     *
     * @param nizkp Proof directory.
     * @param index Index of mix-server.
     * @return File where shrinking list is stored.
     */
    protected static File KLfile(final File nizkp, final int index) { // NOPMD
        return new File(nizkp, String.format("KeepList%02d.bt", index));
    }

    /**
     * Generate permutation commitment.
     *
     * @param log Logging context.
     * @param raisedExponent Secret exponent used to speed up
     * verification of commitment consistent proofs of shuffles.
     */
    public void generate(final Log log, final PRingElement raisedExponent) {

        final int size = generators.size();
        ByteTreeReader reader;
        final File permCommFile = getFile("Commitment");
        final File raisedPermCommFile = getFile("RaisedCommitment");

        log.info("Generate permutation commitment of "
                 + ui.getDescrString(l) + ".");
        final Log tempLog = log.newChildLog();

        if (l == j) {

            if (fromFile) {

                // If we are the committer then we have already read
                // the data we need from file in the call to
                // precompute(Log).
                return;
            }

        } else {

            if (permCommFile.exists()) {

                // Read permutation commitment
                tempLog.info("Read permutation commitment from file.");
                reader = new ByteTreeReaderF(permCommFile);
                commitment = pGroup.unsafeToElementArray(size, reader);
                reader.close();

                // Read permutation commitment
                tempLog.info("Read raised permutation commitment from file.");
                reader = new ByteTreeReaderF(raisedPermCommFile);
                raisedCommitment = pGroup.unsafeToElementArray(size, reader);
                reader.close();

                // If we read data from file, then all parties have
                // it, there is no need to interact, and we return.
                return;
            }
        }

        // We did not read from file, so we need to interact and
        // prove/verify using a proof of a shuffle of commitments.
        this.posc = poscFactory.newPoSC("", this, rosid, nizkp);

        if (l == j) {

            // Publish permutation commitment
            tempLog.info("Publish permutation commitment.");
            bullBoard.publish("Commitment", commitment.toByteTree(), tempLog);

            // Prove knowledge of commitment exponents.
            posc.prove(tempLog,
                       pGroup.getg(),
                       generators,
                       commitment,
                       exponents,
                       permutation);

        } else {

            // We assume to start with that we should not replace the
            // commitment with a trivial one.
            boolean trivial = false;

            // Read permutation commitment.
            tempLog.info("Read permutation commitment of "
                         + ui.getDescrString(l) + ".");
            final ByteTreeReader commitmentReader =
                bullBoard.waitFor(l, "Commitment", tempLog);
            try {

                commitment = pGroup.toElementArray(size, commitmentReader);

            } catch (final ArithmFormatException afe) {
                trivial = true;
            } finally {
                commitmentReader.close();
            }

            // Verify knowledge of commitment exponents.
            if (!trivial) {

                trivial = !posc.verify(tempLog,
                                       l,
                                       pGroup.getg(),
                                       generators,
                                       commitment);
            }

            if (trivial) {

                // If there is any error we set the commitment to the
                // trivial one.
                tempLog.info("Trivial commitment of identity permutation.");
                commitment = generators.copyOfRange(0, generators.size());
            }

            tempLog.info("Write permutation commitment to file.");
            commitment.toByteTree().unsafeWriteTo(permCommFile);

            // This is used to speed up verification of
            // commitment-consistent proofs of shuffles.
            tempLog.info("Compute raised permutation commitment.");
            raisedCommitment = commitment.exp(raisedExponent);

            tempLog.info("Write raised permutation commitment to file.");
            raisedCommitment.toByteTree().unsafeWriteTo(raisedPermCommFile);
        }

        if (nizkp != null) {
            commitment.toByteTree().unsafeWriteTo(PCfile(nizkp, l));
        }
    }

    /**
     * Returns the number of true values in the list.
     *
     * @param list Number of true values in the list.
     * @return Number of true values in input.
     */
    protected int count(final boolean[] list) {
        int total = 0;
        for (int i = 0; i < list.length; i++) {
            if (list[i]) {
                total++;
            }
        }
        return total;
    }

    /**
     * Shrinks this instance to the given size.
     *
     * @param log Logging context.
     * @param noCiphertexts Number of ciphertexts after shrinking.
     */
    public void shrink(final Log log, final int noCiphertexts) {

        log.info("Shrink permutation commitment of " + ui.getDescrString(l));
        final Log tempLog = log.newChildLog();

        // This list indicates the elements to keep.
        boolean[] keepList = null;

        if (l == j) {

            // Figure out which elements in the permutation commitment
            // we should keep.
            keepList = new boolean[permutation.size()];
            for (int i = 0; i < noCiphertexts; i++) {
                keepList[permutation.map(i)] = true;
            }

            // Publish keep list.
            tempLog.info("Publish keep list.");
            final ByteTree bt = ByteTree.booleanArrayToByteTree(keepList);
            bullBoard.publish("KeepList", bt, tempLog);

            if (nizkp != null) {
                bt.unsafeWriteTo(KLfile(nizkp, j));
            }

            // Shrink private data.
            tempLog.info("Shrink commitment exponents.");
            final PRingElementArray oldExponents = exponents;
            exponents = exponents.copyOfRange(0, noCiphertexts);
            oldExponents.free();

            tempLog.info("Shrink permutation.");
            permutation = permutation.shrink(noCiphertexts);

        } else {

            boolean trivial = false;

            // Read and verify that the input is an array of booleans.
            tempLog.info("Read keep list.");
            final ByteTreeReader btr =
                bullBoard.waitFor(l, "KeepList", tempLog);
            try {
                keepList = btr.readBooleans(commitment.size());
            } catch (final EIOException eioe) {
                trivial = true;
            } finally {
                btr.close();
            }

            // Verify that the expected number of elements is chosen.
            if (!trivial && count(keepList) != noCiphertexts) {
                trivial = true;
            }

            // Set to trivial array if there is a problem.
            if (trivial) {
                keepList = new boolean[commitment.size()];
                Arrays.fill(keepList, 0, noCiphertexts, true);
            }
        }

        if (nizkp != null) {
            final ByteTreeBasic bt = ByteTree.booleanArrayToByteTree(keepList);
            bt.unsafeWriteTo(KLfile(nizkp, l));
        }

        // Use the keep list to extract a smaller permutation
        // commitment.
        tempLog.info("Shrink permutation commitment.");
        final PGroupElementArray oldCommitment = commitment;
        commitment = commitment.extract(keepList);
        oldCommitment.free();

        if (l != j) {
            tempLog.info("Shrink raised permutation commitment.");
            final PGroupElementArray oldRaisedCommitment = raisedCommitment;
            raisedCommitment = raisedCommitment.extract(keepList);
            oldRaisedCommitment.free();
        }
    }

    /**
     * Returns the generated permutation.
     *
     * @return Underlying permutation.
     */
    public Permutation getPermutation() {
        return permutation;
    }

    /**
     * Returns the exponents used to form the commitment.
     *
     * @return Exponents used to form the commitment.
     */
    public PRingElementArray getExponents() {
        return exponents;
    }

    /**
     * Returns the permutation commitment.
     *
     * @return Permutation commitment.
     */
    public PGroupElementArray getCommitment() {
        return commitment;
    }

    /**
     * Returns the raised permutation commitment.
     *
     * @return Raised permutation commitment.
     */
    public PGroupElementArray getRaisedCommitment() {
        return raisedCommitment;
    }

    /**
     * Frees any resources allocated by this instance.
     */
    public void free() {

        if (identityCommitment != null) {
            identityCommitment.free();
        }
        if (exponents != null) {
            exponents.free();
        }
        if (commitment != null) {
            commitment.free();
        }
        if (raisedCommitment != null) {
            raisedCommitment.free();
        }
    }
}
