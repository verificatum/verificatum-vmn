
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
