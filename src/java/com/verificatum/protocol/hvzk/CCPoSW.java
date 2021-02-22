
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

package com.verificatum.protocol.hvzk;

import java.io.File;

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;

/**
 * Implementation of Wikstrom's commitment-consistent proof of a
 * shuffle.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions",
                   "PMD.SingletonClassReturningNewInstanceRule"})
public final class CCPoSW extends ProtocolElGamal implements CCPoS {

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
    public CCPoSW(final String sid,
                  final ProtocolElGamal protocol,
                  final String rosid,
                  final File nizkp) {
        super(sid, protocol, rosid, nizkp);
    }

    // Documented in PoS.java

    @Override
    public void prove(final Log log,
                      final PGroupElement g,
                      final PGroupElementArray h,
                      final PGroupElementArray u,
                      final PGroupElement pkey,
                      final PGroupElementArray w,
                      final PGroupElementArray wp,
                      final PRingElementArray r,
                      final Permutation pi,
                      final PRingElementArray s) {

        log.info("Prove correctness of shuffle.");
        final Log tempLog = log.newChildLog();

        final CCPoSBasicW P =
            new CCPoSBasicW(vbitlen(), ebitlen(), rbitlen, prg);

        P.setInstance(g, h, u, pkey, w, wp, r, pi, s);

        // Generate a seed to the PRG for batching.
        tempLog.info("Generate batching vector.");
        Log tempLog2 = tempLog.newChildLog();

        ByteTreeContainer challengeData =
            new ByteTreeContainer(g.toByteTree(),
                                  h.toByteTree(),
                                  u.toByteTree(),
                                  pkey.toByteTree(),
                                  w.toByteTree(),
                                  wp.toByteTree());
        final byte[] prgSeed = challenger.challenge(tempLog2,
                                                    challengeData,
                                                    8 * prg.minNoSeedBytes(),
                                                    rbitlen);

        // Compute and publish commitment.
        tempLog.info("Compute commitment.");
        final ByteTreeBasic commitment = P.commit(prgSeed, randomSource);

        Thread commitmentExportThread = null;
        if (nizkp != null) {
            commitmentExportThread = new Thread() {
                    @Override
                    public void run() {
                        commitment.unsafeWriteTo(CCPoSCfile(nizkp, j));
                    }
                };
            commitmentExportThread.start();
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
            reply.unsafeWriteTo(CCPoSRfile(nizkp, j));
        }

        tempLog.info("Publish reply.");
        bullBoard.publish("Reply", reply, tempLog);

        P.free();

        if (commitmentExportThread != null) {
            try {
                commitmentExportThread.join();
            } catch (final InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public boolean verify(final Log log,
                          final int l,
                          final PGroupElement g,
                          final PGroupElementArray h,
                          final PGroupElementArray u,
                          final PGroupElement pkey,
                          final PGroupElementArray w,
                          final PGroupElementArray wp,
                          final PGroupElementArray raisedu,
                          final PGroupElementArray raisedh,
                          final PRingElement raisedExponent) {

        log.info("Verify correctness of shuffle of " + ui.getDescrString(l)
                 + ".");
        final Log tempLog = log.newChildLog();

        final CCPoSBasicW V =
            new CCPoSBasicW(vbitlen(), ebitlen(), rbitlen, prg);
        V.setInstance(g, h, u, pkey, w, wp);

        // Generate a seed to the PRG for batching.
        tempLog.info("Generate batching vector.");
        Log tempLog2 = tempLog.newChildLog();

        ByteTreeContainer challengeData =
            new ByteTreeContainer(g.toByteTree(),
                                  h.toByteTree(),
                                  u.toByteTree(),
                                  pkey.toByteTree(),
                                  w.toByteTree(),
                                  wp.toByteTree());
        final byte[] prgSeed = challenger.challenge(tempLog2,
                                                    challengeData,
                                                    8 * prg.minNoSeedBytes(),
                                                    rbitlen);
        V.setBatchVector(prgSeed);

        tempLog.info("Batch.");

        // Compute A and B.
        V.computeAB(raisedu);

        // Read and set the commitment of the prover.
        tempLog.info("Read the commitment.");

        final ByteTreeReader commitmentReader =
            bullBoard.waitFor(l, "Commitment", tempLog);
        final ByteTreeBasic commitment = V.setCommitment(commitmentReader);
        commitmentReader.close();

        Thread commitmentExportThread = null;
        if (nizkp != null) {
            commitmentExportThread = new Thread() {
                    @Override
                    public void run() {
                        commitment.unsafeWriteTo(CCPoSCfile(nizkp, l));
                    }
                };
            commitmentExportThread.start();
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
        final boolean verdict = V.verify(replyReader, raisedh, raisedExponent);
        replyReader.close();

        if (nizkp != null) {
            V.getReply().unsafeWriteTo(CCPoSRfile(nizkp, l));
        }

        if (verdict) {
            tempLog.info("Accepted proof.");
        } else {
            tempLog.info("Rejected proof.");
        }

        V.free();

        if (commitmentExportThread != null) {
            try {
                commitmentExportThread.join();
            } catch (final InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }

        return verdict;
    }

    /**
     * Name of file containing commitment of proof of shuffle.
     *
     * @param nizkp Export directory for universal verifiability.
     * @param index index of mix-server.
     * @return File where permutation commitments are stored.
     */
    public static File CCPoSCfile(final File nizkp, final int index) {
        return new File(nizkp,
                        String.format("CCPoSCommitment%02d.bt", index));
    }

    /**
     * Name of file containing reply of proof of shuffle.
     *
     * @param nizkp Export directory for universal verifiability.
     * @param index index of mix-server.
     * @return File where permutation commitments are stored.
     */
    public static File CCPoSRfile(final File nizkp, final int index) {
        return new File(nizkp, String.format("CCPoSReply%02d.bt", index));
    }
}
