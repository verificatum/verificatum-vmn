
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

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.ModPGroup;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ExtIO;
import com.verificatum.test.TestClass;
import com.verificatum.test.TestParameters;

/**
 * Tests some of the functionality of {@link PoSCBasicTW}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public final class TestPoSCBasicTW extends TestClass {

    /**
     * Constructor needed to avoid that this class is instantiated.
     *
     * @param tp Test parameters configuration of the servers.
     */
    public TestPoSCBasicTW(final TestParameters tp) {
        super(tp);
    }

    /**
     * Instantiate a random source to be used by the other methods.
     *
     * @param correct Determines if the test should fail or not.
     * @return Return result of test.
     * @throws Exception when failing test.
     */
    protected int runTest(final boolean correct)
        throws Exception {

        // Set up context

        final PGroup pGroup = new ModPGroup(512);

        final int size = 100;

        final int ebitlen = 100;
        final int vbitlen = 100;
        final int rbitlen = 50;

        final RandomSource rs = new PRGHeuristic(ExtIO.getBytes(tp.prgseed));
        final PRG prg = new PRGHeuristic();

        final byte[] prgSeed = rs.getBytes(prg.minNoSeedBytes());

        // Create instance

        final PGroupElement g = pGroup.getg();
        final PGroupElementArray h =
            g.exp(pGroup.getPRing().randomElementArray(size, rs, rbitlen));

        PRingElementArray r =
            pGroup.getPRing().randomElementArray(size, rs, rbitlen);

        PGroupElementArray u = g.exp(r).mul(h);

        final Permutation pi = Permutation.random(size, rs, rbitlen);

        u = u.permute(pi);

        // Execute the protocol

        final PoSCBasicTW P = new PoSCBasicTW(vbitlen, ebitlen,
                                              rbitlen, prg, rs);

        final PoSCBasicTW V = new PoSCBasicTW(vbitlen, ebitlen,
                                              rbitlen, prg, rs);
        if (!correct) {
            r = r.add(r);
        }

        P.setInstance(g, h, u, r, pi);
        V.setInstance(g, h, u);

        final ByteTreeBasic commitment = P.commit(prgSeed);

        V.setBatchVector(prgSeed);

        final ByteTreeReader btrCommit = commitment.getByteTreeReader();
        V.setCommitment(btrCommit);
        btrCommit.close();

        final LargeInteger integerChallenge =
            new LargeInteger(P.getVbitlen(), rs);

        V.setChallenge(integerChallenge);

        final ByteTreeBasic reply = P.reply(integerChallenge);

        final ByteTreeReader btrReply = reply.getByteTreeReader();
        final boolean verdict = V.verify(btrReply);
        btrReply.close();

        if (verdict) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Verifies that a correctly computed proof is accepted.
     *
     * @throws Exception when failing test.
     */
    public void acceptingTranscript()
        throws Exception {
        assert runTest(true) == 1
            : "Failed to test accepting transcript!";
    }

    /**
     * Verifies that some types of incorrectly computed proofs are
     * rejected.
     *
     * @throws Exception when failing test.
     */
    public void rejectingTranscript()
        throws Exception {
        assert runTest(false) == 0
            : "Failed to test rejecting transcript!";
    }
}
