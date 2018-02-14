
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

package com.verificatum.protocol.hvzk;

import java.io.File;

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;


/**
 * Implementation of Terelius-Wikstrom proof of a shuffle.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions",
                   "PMD.SingletonClassReturningNewInstanceRule"})
public final class PoSTW extends ProtocolElGamal implements PoS {

    /**
     * Basic proof instance.
     */
    PoSBasicTW P;

    /**
     * Basic proof instance.
     */
    PoSBasicTW V;

    /**
     * Creates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * #deleteState()} is called.
     */
    public PoSTW(final String sid,
                 final ProtocolElGamal protocol,
                 final String rosid,
                 final File nizkp) {
        super(sid, protocol, rosid, nizkp);
    }

    // Documented in PoS.java

    @Override
    public void precompute(final Log log,
                           final PGroupElement g,
                           final PGroupElementArray h,
                           final Permutation pi) {

        P = new PoSBasicTW(vbitlen(), ebitlen(), rbitlen, prg, randomSource);
        log.info("Compute permutation commitment.");
        P.precompute(g, h, pi);
    }

    @Override
    public void prove(final Log log,
                      final PGroupElement pkey,
                      final PGroupElementArray w,
                      final PGroupElementArray wp,
                      final PRingElementArray s) {

        log.info("Prove correctness of shuffle.");
        final Log tempLog = log.newChildLog();

        P.setInstance(pkey, w, wp, s);

        // Publish our commitment of a permutation.
        tempLog.info("Publish our permutation commitment.");
        bullBoard.publish("PermutationCommitment", P.u.toByteTree(), tempLog);

        if (nizkp != null) {
            P.u.toByteTree().unsafeWriteTo(PCfile(nizkp, j));
        }

        // Generate a seed to the PRG for batching.
        tempLog.info("Generate batching vector.");
        Log tempLog2 = tempLog.newChildLog();

        ByteTreeContainer challengeData =
            new ByteTreeContainer(P.g.toByteTree(),
                                  P.h.toByteTree(),
                                  P.u.toByteTree(),
                                  pkey.toByteTree(),
                                  w.toByteTree(),
                                  wp.toByteTree());

        final byte[] prgSeed =
            challenger.challenge(tempLog2,
                                 challengeData,
                                 8 * prg.minNoSeedBytes(),
                                 rbitlen);

        // Compute and publish commitment.
        tempLog.info("Compute commitment.");
        final ByteTreeBasic commitment = P.commit(prgSeed);

        if (nizkp != null) {
            commitment.unsafeWriteTo(PoSCfile(nizkp, j));
        }

        tempLog.info("Publish our commitment.");
        bullBoard.publish("Commitment", commitment, tempLog);

        // Generate a challenge.
        tempLog.info("Generate challenge.");
        tempLog2 = tempLog.newChildLog();
        challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
        final byte[] challengeBytes =
            challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        // Compute and publish reply.
        tempLog.info("Compute reply.");
        final ByteTreeBasic reply = P.reply(integerChallenge);

        if (nizkp != null) {
            reply.unsafeWriteTo(PoSRfile(nizkp, j));
        }

        tempLog.info("Publish reply.");
        bullBoard.publish("Reply", reply, tempLog);

        P.free();
    }

    @Override
    public void precompute(final Log log,
                           final PGroupElement g,
                           final PGroupElementArray h) {

        V = new PoSBasicTW(vbitlen(), ebitlen(), rbitlen, prg, randomSource);
        V.precompute(g, h);
    }

    @Override
    public boolean verify(final Log log,
                          final int l,
                          final PGroupElement pkey,
                          final PGroupElementArray w,
                          final PGroupElementArray wp) {

        log.info("Verify correctness of shuffle of " + ui.getDescrString(l)
                 + ".");
        final Log tempLog = log.newChildLog();

        V.setInstance(pkey, w, wp);

        // Read and set the permutation commitment of the prover.
        tempLog.info("Read the permutation commitment.");
        final ByteTreeReader permutationCommitmentReader =
            bullBoard.waitFor(l, "PermutationCommitment", tempLog);
        V.setPermutationCommitment(permutationCommitmentReader);
        permutationCommitmentReader.close();

        if (nizkp != null) {
            V.u.toByteTree().unsafeWriteTo(PCfile(nizkp, l));
        }

        // Generate a seed to the PRG for batching.
        tempLog.info("Generate batching vector.");
        Log tempLog2 = tempLog.newChildLog();

        ByteTreeContainer challengeData =
            new ByteTreeContainer(V.g.toByteTree(),
                                  V.h.toByteTree(),
                                  V.u.toByteTree(),
                                  pkey.toByteTree(),
                                  w.toByteTree(),
                                  wp.toByteTree());

        final byte[] prgSeed = challenger.challenge(tempLog2,
                                                    challengeData,
                                                    8 * prg.minNoSeedBytes(),
                                                    rbitlen);

        V.setBatchVector(prgSeed);

        tempLog.info("Batch.");

        // We can compute A and F in parallel with the prover
        // computing the rest of the proof.
        V.computeAF();

        // Read and set the commitment of the prover.
        tempLog.info("Read the commitment.");

        final ByteTreeReader commitmentReader =
            bullBoard.waitFor(l, "Commitment", tempLog);
        final ByteTreeBasic commitment = V.setCommitment(commitmentReader);
        commitmentReader.close();

        if (nizkp != null) {
            commitment.unsafeWriteTo(PoSCfile(nizkp, l));
        }

        // Generate a challenge
        tempLog.info("Generate challenge.");
        tempLog2 = tempLog.newChildLog();
        challengeData =
            new ByteTreeContainer(new ByteTree(prgSeed), commitment);
        final byte[] challengeBytes =
            challenger.challenge(tempLog2, challengeData, vbitlen(), rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);

        // Set the commitment and challenge.
        V.setChallenge(integerChallenge);

        // Read and verify reply.
        tempLog.info("Read the reply.");
        final ByteTreeReader replyReader =
            bullBoard.waitFor(l, "Reply", tempLog);

        tempLog.info("Perform verification.");
        final boolean verdict = V.verify(replyReader);
        replyReader.close();

        if (verdict && nizkp != null) {
            V.getReply().unsafeWriteTo(PoSRfile(nizkp, l));
        }

        if (verdict) {
            tempLog.info("Accepted proof.");
        } else {
            tempLog.info("Rejected proof.");
        }

        V.free();

        return verdict;
    }

    /**
     * Name of file containing permutation commitment.
     *
     * @param nizkp Export directory for universal verifiability.
     * @param index Index of party.
     * @return File where permutation commitments are stored.
     */
    public static File PCfile(final File nizkp, final int index) {
        return new File(nizkp,
                        String.format("PermutationCommitment%02d.bt", index));
    }

    /**
     * Name of file containing commitment of proof of shuffle.
     *
     * @param nizkp Directory containing proofs.
     * @param index index of mix-server.
     * @return File where permutation commitments are stored.
     */
    public static File PoSCfile(final File nizkp, final int index) {
        return new File(nizkp,
                        String.format("PoSCommitment%02d.bt", index));
    }

    /**
     * Name of file containing reply of proof of shuffle.
     *
     * @param nizkp Directory containing proofs.
     * @param index index of mix-server.
     * @return File where permutation commitments are stored.
     */
    public static File PoSRfile(final File nizkp, final int index) {
        return new File(nizkp, String.format("PoSReply%02d.bt", index));
    }

    @Override
    public void free() {
        if (P != null) {
            P.free();
        }
        if (V != null) {
            V.free();
        }
    }
}
