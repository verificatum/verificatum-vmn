
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PFieldElementArray;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;


/**
 * Public-coin zero-knowledge proof functionality needed to generate a
 * list of independent generators, i.e., a list of generators for
 * which finding any non-trivial representation implies that the
 * discrete logarithm assumption is violated.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions"})
public final class IndependentGeneratorsBasicI {

    /**
     * Index of this party.
     */
    int j;

    /**
     * Threshold number of parties needed to execute the protocol.
     */
    int threshold;

    /**
     * Bit-size of each component when batching.
     */
    int ebitlen;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * PRG used for batching.
     */
    PRG prg;

    /**
     * Standard generator.
     */
    PGroupElement g;

    /**
     * Parts of independent generators.
     */
    PGroupElementArray[] h;

    /**
     * Secret exponents of this party.
     */
    PRingElementArray s;

    /**
     * Independent generators.
     */
    PGroupElementArray combinedh;

    /**
     * Blinder exponent used in zero-knowledge proof.
     */
    PRingElement r;

    /**
     * Blinder elements used in zero-knowledge proof.
     */
    PGroupElement[] Ap;

    /**
     * Vector of random exponents.
     */
    PFieldElementArray e;

    /**
     * Batched exponents of this party.
     */
    PRingElement a;

    /**
     * Replies for batched exponents.
     */
    PRingElement[] k_a;

    /**
     * Challenge as field element.
     */
    PFieldElement v;

    /**
     * Creates an instance of the protocol.
     *
     * @param j Index of this party.
     * @param threshold Number of parties needed to recover the secret
     * key.
     * @param ebitlen Number of bits in each component when
     * batching.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param prg PRG used for batching homomorphisms that allow this.
     */
    public IndependentGeneratorsBasicI(final int j,
                                       final int threshold,
                                       final int ebitlen,
                                       final int rbitlen,
                                       final PRG prg) {
        this.j = j;
        this.threshold = threshold;
        this.ebitlen = ebitlen;
        this.rbitlen = rbitlen;
        this.prg = prg;

        this.Ap = new PGroupElement[threshold + 1];
        this.k_a = new PRingElement[threshold + 1];
    }

    /**
     * Initializes this instance.
     *
     * @param g Basic generator.
     * @param h Parts of generators.
     * @param s Exponents used to construct the generators parts of
     * this party.
     * @param combinedh Combined generators.
     */
    public void setInstance(final PGroupElement g,
                            final PGroupElementArray[] h,
                            final PRingElementArray s,
                            final PGroupElementArray combinedh) {
        this.g = g;
        this.h = Arrays.copyOf(h, h.length);
        this.s = s;
        this.combinedh = combinedh;
    }

    /**
     * BOTH: Extracts the random vector from a random seed using a
     * pseudo-random generator.
     *
     * @param prgSeed Seed to the pseudorandom generator used to
     * extract the random vector.
     */
    public void setBatchVector(final byte[] prgSeed) {
        prg.setSeed(prgSeed);
        final LargeIntegerArray lia =
            LargeIntegerArray.random(h[1].size(), ebitlen, prg);

        this.e = h[1].getPGroup().getPRing().getPField()
            .unsafeToElementArray(lia);
    }

    /**
     * Compute commitment of this party.
     *
     * @param randomSource Source of randomness.
     * @return Commitment.
     */
    public ByteTreeBasic commit(final RandomSource randomSource) {
        a = s.innerProduct(e);

        r = a.getPRing().randomElement(randomSource, rbitlen);
        Ap[j] = g.exp(r);

        return Ap[j].toByteTree();
    }

    /**
     * Set commitment of the given party. If reading fails, then the
     * commitment is set to the unit in the group.
     *
     * @param l Index of other party.
     * @param commitmentReader Source of commitment.
     */
    public void setCommitment(final int l,
                              final ByteTreeReader commitmentReader) {
        try {
            Ap[l] = h[1].getPGroup().toElement(commitmentReader);
        } catch (final ArithmFormatException afe) {
            Ap[l] = h[1].getPGroup().getONE();
        }
    }

    /**
     * Set challenge.
     *
     * @param integerChallenge Challenge integer.
     */
    public void setChallenge(final LargeInteger integerChallenge) {
        final PField pField = h[1].getPGroup().getPRing().getPField();
        v = pField.toElement(integerChallenge);
    }

    /**
     * Compute the reply of this party.
     *
     * @return Reply of this party.
     */
    public ByteTreeBasic reply() {
        k_a[j] = a.mul(v).add(r);
        return k_a[j].toByteTree();
    }

    /**
     * Set reply of the given party. If the reply can not be read,
     * then it is set to zero.
     *
     * @param l Index of other party.
     * @param replyReader Source of reply.
     */
    public void setReply(final int l, final ByteTreeReader replyReader) {

        final PRing pRing = h[1].getPGroup().getPRing();
        try {
            k_a[l] = pRing.toElement(replyReader);
        } catch (final ArithmFormatException afe) {
            k_a[l] = pRing.getZERO();
        }
    }

    /**
     * Verify the combined proof.
     *
     * @return Verdict for the combined proof.
     */
    public boolean verify() {

        // Compute combined proof.
        PRingElement combinedk_a = k_a[1].getPRing().getZERO();
        PGroupElement combinedAp = Ap[1].getPGroup().getONE();

        for (int l = 1; l <= threshold; l++) {
            combinedk_a = combinedk_a.add(k_a[l]);
            combinedAp = combinedAp.mul(Ap[l]);
        }

        // Batch independent generators.
        final PGroupElement combinedA = combinedh.expProd(e);

        return combinedA.exp(v).mul(combinedAp).equals(g.exp(combinedk_a));
    }

    /**
     * Verify proof of the given party.
     *
     * @param l Index of other party.
     * @return Verdict for the combined proof.
     */
    public boolean verify(final int l) {
        return h[l].expProd(e).exp(v).mul(Ap[l]).equals(g.exp(k_a[l]));
    }
}
