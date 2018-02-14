
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
