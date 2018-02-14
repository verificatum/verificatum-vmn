
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

import java.util.Arrays;

import com.verificatum.crypto.Hashdigest;
import com.verificatum.crypto.Hashfunction;
import com.verificatum.crypto.RandomOracle;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.ui.Log;


/**
 * Container class for a random oracle used to produce challenges in
 * public coin protocols.
 *
 * @author Douglas Wikstrom
 */
public final class ChallengerRO implements Challenger {

    /**
     * Hashfunction used to construct random oracles.
     */
    Hashfunction roHashfunction;

    /**
     * Prefix used with each invocation of the random oracle.
     */
    byte[] globalPrefix;

    /**
     * Creates an instance which generates challenges using a
     * "random oracle" constructed from the given hashfunction.
     *
     * <p>
     *
     * WARNING! The hashfunction must be "cryptographically strong",
     * e.g., SHA-256 has this property, a collision-resistant
     * hashfunction is not enough.
     *
     * @param roHashfunction Hashfunction used to construct random
     * oracles.
     * @param globalPrefix Prefix used with each invocation of the
     * random oracle.
     */
    public ChallengerRO(final Hashfunction roHashfunction,
                        final byte[] globalPrefix) {
        this.roHashfunction = roHashfunction;
        this.globalPrefix = Arrays.copyOf(globalPrefix, globalPrefix.length);
    }

    /**
     * Returns a challenge.
     *
     * @param data Input to the random oracle. This should contain the
     * instance and the messages up to the challenge step.
     * @param vbitlen Number of bits to generate.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @return Challenge bytes.
     */
    public byte[] challenge(final ByteTreeBasic data,
                            final int vbitlen,
                            final int rbitlen) {
        return challenge(null, data, vbitlen, rbitlen);
    }

    // Documented in Challenger.java

    @Override
    public byte[] challenge(final Log log,
                            final ByteTreeBasic data,
                            final int vbitlen,
                            final int rbitlen) {
        if (log != null) {
            log.info("Derive " + vbitlen + " bits using random oracle.");
        }

        // Define a random oracle with the given output length.
        final RandomOracle ro = new RandomOracle(roHashfunction, vbitlen);

        // Compute the digest of the byte tree.
        final Hashdigest d = ro.getDigest();

        d.update(globalPrefix);
        data.update(d);

        final byte[] digest = d.digest();

        return digest;
    }
}
