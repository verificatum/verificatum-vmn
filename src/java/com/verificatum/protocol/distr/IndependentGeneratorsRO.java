
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

package com.verificatum.protocol.distr;

import java.util.Arrays;

import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.crypto.Hashdigest;
import com.verificatum.crypto.Hashfunction;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomOracle;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ExtIO;
import com.verificatum.ui.Log;


/**
 * Uses a "random oracle" to derive a list of "independent"
 * generators, i.e., a list of generators for which finding any
 * non-trivial representation implies that the discrete logarithm
 * assumption is violated.
 *
 * @author Douglas Wikstrom
 */
public final class IndependentGeneratorsRO implements IndependentGenerators {

    /**
     * Hashfunction on which the "random oracle" is based.
     */
    Hashfunction roHashfunction;

    /**
     * Prefix used with each invocation of the random oracle.
     */
    byte[] globalPrefix;

    /**
     * Decides the statistical distance from the uniform distribution
     * assuming that the random oracle is truly random.
     */
    int rbitlen;

    /**
     * Session identifier distinguishing this derivation from other.
     */
    String sid;

    /**
     * Creates an instance. It is the responsibility of the user to
     * ensure that the session identifier is unique among all
     * applications that should give different "independent" arrays of
     * generators.
     *
     * @param sid Session identifier which separates this derivation
     * from others.
     * @param roHashfunction Hashfunction on which the random oracle
     * is based.
     * @param globalPrefix Prefix used with each invocation of the
     * random oracle used to derive the independent
     * generators.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution assuming that the random oracle
     * is truly random.
     */
    public IndependentGeneratorsRO(final String sid,
                                   final Hashfunction roHashfunction,
                                   final byte[] globalPrefix,
                                   final int rbitlen) {
        this.sid = sid;
        this.roHashfunction = roHashfunction;
        this.globalPrefix = Arrays.copyOf(globalPrefix, globalPrefix.length);
        this.rbitlen = rbitlen;
    }

    /**
     * Generate the independent generators.
     *
     * @param log Logging context.
     * @param pGroup Underlying group.
     * @param numberOfGenerators Number of generators to generate.
     * @return Independent generators.
     */
    @Override
    public PGroupElementArray generate(final Log log,
                                       final PGroup pGroup,
                                       final int numberOfGenerators) {
        if (log != null) {
            log.info("Derive independent generators using RO.");
        }

        final PRG prg = new PRGHeuristic(roHashfunction);
        final RandomOracle ro = new RandomOracle(roHashfunction,
                                                 8 * prg.minNoSeedBytes());

        final Hashdigest d = ro.getDigest();
        d.update(globalPrefix);
        d.update(new ByteTree(ExtIO.getBytes(sid)).toByteArray());

        final byte[] seed = d.digest();

        prg.setSeed(seed);

        return pGroup.randomElementArray(numberOfGenerators, prg, rbitlen);
    }
}
