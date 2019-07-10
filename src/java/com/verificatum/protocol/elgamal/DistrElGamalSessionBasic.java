
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

package com.verificatum.protocol.elgamal;

import java.util.Arrays;

import com.verificatum.arithm.ArithmException;
import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PFieldElementArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.protocol.ProtocolError;


/**
 * Implements a verifiable decryption protocol.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions"})
public final class DistrElGamalSessionBasic {

    /**
     * Index of this party.
     */
    int j;

    /**
     * Basic public key.
     */
    PGroupElement g;

    /**
     * Left components of the ciphertexts.
     */
    PGroupElementArray u;

    /**
     * Public keys.
     */
    PGroupElement[] y;

    /**
     * Combined public key.
     */
    PGroupElement combinedy;

    /**
     * Proof commitments for the public key.
     */
    PGroupElement[] yp;

    /**
     * Combined proof commitment for the public key.
     */
    PGroupElement combinedyp;

    /**
     * Decryption factors.
     */
    PGroupElementArray[] f;

    /**
     * Combined decryption factors.
     */
    PGroupElementArray combinedf;

    /**
     * Secret key of this party.
     */
    PRingElement x;

    /**
     * Batched left components of the ciphertexts.
     */
    PGroupElement A;

    /**
     * Batched decryption factors.
     */
    PGroupElement[] B;

    /**
     * Batched combined decryption factors.
     */
    PGroupElement combinedB;

    /**
     * Proof commitment for batched decryption factors.
     */
    PGroupElement[] Bp;

    /**
     * Proof commitment for batched combined decryption factors.
     */
    PGroupElement combinedBp;

    /**
     * Batching vector.
     */
    PFieldElementArray e;

    /**
     * Blinder exponent.
     */
    PRingElement r;

    /**
     * Replies.
     */
    PRingElement[] k_x;

    /**
     * Combined reply.
     */
    PRingElement combinedk_x;

    /**
     * Number of parties involved.
     */
    int k;

    /**
     * Threshold number of parties needed to decrypt.
     */
    int threshold;

    /**
     * Verdicts of all parties.
     */
    boolean[] verdicts;

    /**
     * Bit length of each element in the batching vector.
     */
    int ebitlen;

    /**
     * Pseudo-random generator used to derive the random vector.
     */
    PRG prg;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Field associated with the ring.
     */
    PField pField;

    /**
     * Inverse of the square of all indices.
     */
    PFieldElement inverseFactor;

    /**
     * List of small prime numbers.
     */
    private static final int[] ODD_PRIME_TABLE =
    {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
     67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
     137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
     199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
     277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353,
     359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
     439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
     521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
     607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677,
     683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
     773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
     863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
     967, 971, 977, 983, 991, 997, 1009};

    /**
     * Constructs a verifiable decryption protocol.
     *
     * @param j Index of this party.
     * @param k Number of parties.
     * @param threshold Number of parties needed to recover the secret
     * key.
     * @param ebitlen Number of bits in each component when
     * batching.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param prg PRG used for batching.
     */
    public DistrElGamalSessionBasic(final int j,
                                    final int k,
                                    final int threshold,
                                    final int ebitlen,
                                    final int rbitlen,
                                    final PRG prg) {
        this.j = j;
        this.k = k;
        this.threshold = threshold;
        this.ebitlen = ebitlen;
        this.rbitlen = rbitlen;
        this.prg = prg;

        this.yp = new PGroupElement[k + 1];
        this.B = new PGroupElement[k + 1];
        this.Bp = new PGroupElement[k + 1];
        this.k_x = new PRingElement[k + 1];

        this.verdicts = new boolean[k + 1];
        Arrays.fill(this.verdicts, true);
    }

    /**
     * Initialize instance.
     *
     * @param g Basic public key.
     * @param u Left components of El Gamal ciphertexts.
     * @param y Public keys.
     * @param f Decryption factors.
     * @param x Secret key of this party.
     * @param combinedy Combined public keys.
     * @param combinedf Combined decryption factors.
     */
    public void setInstance(final PGroupElement g,
                            final PGroupElementArray u,
                            final PGroupElement[] y,
                            final PGroupElementArray[] f,
                            final PRingElement x,
                            final PGroupElement combinedy,
                            final PGroupElementArray combinedf) {
        this.g = g;
        this.u = u;
        this.y = Arrays.copyOf(y, y.length);
        this.f = Arrays.copyOf(f, f.length);
        this.x = x;

        this.combinedy = combinedy;
        this.combinedf = combinedf;

        this.pField = g.getPGroup().getPRing().getPField();

        try {
            inverseFactor = prodFactor(pField, k).inv();
        } catch (final ArithmException ae) {
            throw new ProtocolError("This should never happen!", ae);
        }
    }

    /**
     * Returns the floor of the logarithm of a given number in prime
     * basis.
     *
     * @param number Main input of the algorithm.
     * @param prime Prime basis of logarithm.
     * @return Floor of the logarithm of a given number in prime
     * basis.
     */
    public static LargeInteger primeLog(final LargeInteger number,
                                        final LargeInteger prime) {

        LargeInteger resA = LargeInteger.ONE;
        LargeInteger resB = LargeInteger.ONE;

        final LargeInteger p = prime;

        while (resB.compareTo(number) <= 0) {
            resA = resB;
            resB = resB.mul(p);
        }
        return resA;
    }

    /**
     * Returns the square of the product of the indices. This is used
     * to implement a trick that speeds up Lagrange interpolation of
     * the plaintexts.
     *
     * @param pField Underlying field.
     * @param k Number of parties.
     * @return Square of product of indices.
     */
    public static PFieldElement prodFactor(final PField pField,
                                           final int k) {

        final int maxParties = ODD_PRIME_TABLE[ODD_PRIME_TABLE.length - 1];

        if (k > maxParties) {
            throw new ProtocolError("Too many parties! ("
                                    + k + ", but at most "
                                    + maxParties + " is allowed.)");
        }

        LargeInteger res = LargeInteger.ONE;

        LargeInteger prime = LargeInteger.TWO;

        final LargeInteger kk = new LargeInteger(k);

        int i = 0;
        while (prime.compareTo(kk) <= 0) {

            res = res.mul(primeLog(kk, prime));
            prime = new LargeInteger(ODD_PRIME_TABLE[i]);
            i++;
        }

        return pField.toElement(res.mul(res));
    }

    /**
     * Computes the Lagrange coefficient of the given index. The
     * threshold set of other indices are defined as the first
     * threshold elements that are true in the input array.
     *
     * @param pField Underlying field.
     * @param correct Array indicating which shares are correct.
     * @param k Number of parties.
     * @param threshold Threshold number of parties needed to recover
     * the secret.
     * @return Array of modified Lagrange coefficients.
     */
    public static LargeInteger[]
        modifiedLagrangeCoefficients(final PField pField,
                                     final boolean[] correct,
                                     final int k,
                                     final int threshold) {

        final PFieldElement prodFactor = prodFactor(pField, k);

        final LargeInteger[] integers = new LargeInteger[threshold];

        int j = 0;
        for (int i = 1; j < threshold && i <= k; i++) {

            if (correct[i]) {

                integers[j] = modifiedLagrangeCoefficient(pField,
                                                          prodFactor,
                                                          correct,
                                                          k,
                                                          threshold,
                                                          i);
                j++;
            }
        }

        if (j < threshold) {
            throw new ProtocolError("Attempting to combine too few "
                                    + "decryption factors!");
        }

        return integers;
    }

    /**
     * Computes the Lagrange coefficient of the given index. The
     * threshold set of other indices are defined as the first
     * threshold elements that are true in the input array.
     *
     * @param pField Underlying field.
     * @param prodFactor Product of indices of correct.
     * @param correct Array indicating which shares are correct.
     * @param k Number of parties.
     * @param threshold Threshold number of parties needed to recover
     * the secret.
     * @param i Index of share for which the Lagrange coefficient is
     * computed.
     * @return Modified Lagrange coefficient.
     */
    protected static LargeInteger
        modifiedLagrangeCoefficient(final PField pField,
                                    final PFieldElement prodFactor,
                                    final boolean[] correct,
                                    final int k,
                                    final int threshold,
                                    final int i) {

        PFieldElement res = prodFactor;

        int t = 0;    // Keeps track of number of correct shares seen so far.

        for (int l = 1; t < threshold && l <= k; l++) {

            if (correct[l]) {

                if (l != i) {

                    res = res.mul(pField.toElement(l));

                    final int s = l - i;
                    final PFieldElement e = pField.toElement(s);

                    try {
                        res = (PFieldElement) res.div(e);
                    } catch (final ArithmException ae) {
                        throw new ProtocolError("This should never happen!",
                                                ae);
                    }

                }

                t++;
            }
        }

        // We output an *integer* with as small as possible absolute
        // value. The integer may be negative.
        final LargeInteger liRes = res.toLargeInteger();
        final LargeInteger altLiRes = liRes.sub(pField.getOrder());

        if (altLiRes.abs().compareTo(liRes) < 0) {
            return altLiRes;
        } else {
            return liRes;
        }
    }

    /**
     * Compute product of decryption factors.
     *
     * @param decryptionFactors Decryption factors to multiply.
     * @param correct Array indicating indices with sharess considered
     * correct so far.
     * @param k Number of parties.
     * @param threshold Threshold number of shares needed to
     * reconstruct secret.
     * @return Combined decryption factors.
     */
    public static PGroupElementArray
        combineDecryptionFactors(final PGroupElementArray[] decryptionFactors,
                                 final boolean[] correct,
                                 final int k,
                                 final int threshold) {

        final PGroupElementArray[] bases = new PGroupElementArray[threshold];

        int j = 0;
        for (int i = 1; j < threshold && i <= k; i++) {

            if (correct[i]) {

                bases[j] = decryptionFactors[i];
                j++;
            }
        }
        if (j < threshold) {
            throw new ProtocolError("Attempting to combine too few "
                                    + "decryption factors!");
        }

        final PGroup pGroup = decryptionFactors[1].getPGroup();
        final PField pField = pGroup.getPRing().getPField();

        final LargeInteger[] integers =
            DistrElGamalSessionBasic.modifiedLagrangeCoefficients(pField,
                                                                  correct,
                                                                  k,
                                                                  threshold);
        int bitLength = 0;
        for (j = 0; j < threshold; j++) {
            if (integers[j].bitLength() > bitLength) {
                bitLength = integers[j].bitLength();
            }
        }

        return pGroup.expProd(bases, integers, bitLength);
    }

    /**
     * Extracts the random vector from a seed. This is useful when the
     * honest verifier is replaced by a coin tossing protocol or when
     * this protocol is used as a subprotocol.
     *
     * @param prgSeed Seed to the pseudorandom generator used to
     * extract the random vector.
     */
    public void setBatchVector(final byte[] prgSeed) {
        prg.setSeed(prgSeed);
        final LargeIntegerArray lia =
            LargeIntegerArray.random(u.size(), ebitlen, prg);
        this.e = pField.unsafeToElementArray(lia);
    }

    /**
     * Computes a batched input from the left components of the
     * ciphertexts.
     */
    public void batchInput() {
        this.A = u.expProd(e);
    }

    /**
     * Compute commitment.
     *
     * @param randomSource Source of randomness.
     * @return Commitment.
     */
    public ByteTreeBasic commit(final RandomSource randomSource) {
        r = g.getPGroup().getPRing().randomElement(randomSource, rbitlen);
        yp[j] = g.exp(r);
        Bp[j] = A.exp(r);

        return new ByteTreeContainer(yp[j].toByteTree(), Bp[j].toByteTree());
    }

    /**
     * Set commitment of the given party.
     *
     * @param l Index of other party.
     * @param commitmentReader Source of commitment.
     */
    public void setCommitment(final int l,
                              final ByteTreeReader commitmentReader) {
        try {
            yp[l] = g.getPGroup().toElement(commitmentReader.getNextChild());
            Bp[l] = u.getPGroup().toElement(commitmentReader.getNextChild());
        } catch (final EIOException eioe) {
            verdicts[l] = false;
        } catch (final ArithmFormatException afe) {
            verdicts[l] = false;
        }
        if (!verdicts[l]) {
            yp[l] = g.getPGroup().getONE();
            Bp[l] = u.getPGroup().getONE();
        }
    }

    /**
     * Returns the commitment of the given party.
     *
     * @param l Index of other party.
     * @return Commitment of the given party.
     */
    public ByteTreeBasic getCommitment(final int l) {
        return new ByteTreeContainer(yp[l].toByteTree(), Bp[l].toByteTree());
    }

    /**
     * Returns a single commitment consisting of all the individual
     * commitments.
     *
     * @return Combined commitment of all parties.
     */
    public ByteTreeBasic getCommitment() {

        final ByteTreeBasic[] bt = new ByteTreeBasic[k];
        for (int l = 0; l < k; l++) {
            bt[l] = getCommitment(l + 1);
        }
        return new ByteTreeContainer(bt);
    }

    /**
     * Computes the reply of this party.
     *
     * @param v Challenge integer.
     * @return Reply.
     */
    public ByteTreeBasic reply(final LargeInteger v) {
        k_x[j] = x.neg().mul(inverseFactor).mul(pField.toElement(v)).add(r);
        return k_x[j].toByteTree();
    }

    /**
     * Set reply of the given party.
     *
     * @param l Index of other party.
     * @param replyReader Source of reply.
     */
    public void setReply(final int l, final ByteTreeReader replyReader) {
        final PRing pRing = g.getPGroup().getPRing();
        try {
            k_x[l] = pRing.toElement(replyReader);
        } catch (final ArithmFormatException afe) {
            k_x[l] = pRing.getZERO();
            verdicts[l] = false;
        }
    }

    /**
     * Returns the reply of the given party.
     *
     * @param l Index of other party.
     * @return Reply.
     */
    public ByteTreeBasic getReply(final int l) {
        return k_x[l].toByteTree();
    }

    /**
     * Returns the verdict for the given party.
     *
     * @param l Index of other party.
     * @return Verdict.
     */
    public boolean getVerdict(final int l) {
        return verdicts[l];
    }

    /**
     * Combines the proof commitments and replies.
     *
     * @param correct Array indicating which shares are considered
     * correct so far.
     */
    public void combine(final boolean[] correct) {

        int t;

        final LargeInteger[] integers =
            modifiedLagrangeCoefficients(pField,
                                         correct,
                                         k,
                                         threshold);

        final PFieldElement[] exponents = new PFieldElement[integers.length];
        for (t = 0; t < threshold; t++) {
            if (integers[t].compareTo(LargeInteger.ZERO) < 0) {
                exponents[t] = pField.toElement(integers[t].neg()).neg();
            } else {
                exponents[t] = pField.toElement(integers[t]);
            }
        }

        combinedyp = yp[1].getPGroup().getONE();
        combinedBp = Bp[1].getPGroup().getONE();
        combinedk_x = k_x[1].getPRing().getZERO();

        t = 0;

        for (int l = 1; t < threshold && l <= k; l++) {

            if (correct[l]) {

                combinedyp = combinedyp.mul(yp[l].exp(exponents[t]));
                combinedBp = combinedBp.mul(Bp[l].exp(exponents[t]));
                combinedk_x = combinedk_x.add(k_x[l].mul(exponents[t]));

                t++;
            }
        }
    }

    /**
     * Batch the combined decryption factors.
     */
    public void batchCombined() {
        combinedB = combinedf.expProd(e);
    }

    /**
     * Verify the the combined proof for the combined instance.
     *
     * @param v Challenge.
     * @return Verdict of verification.
     */
    public boolean verifyCombined(final LargeInteger v) {

        final PFieldElement pfev = pField.toElement(v);
        return combinedy.inv().exp(pfev).mul(combinedyp).
            equals(g.exp(combinedk_x))
            && combinedB.exp(pfev).mul(combinedBp).
            equals(A.exp(combinedk_x));
    }

    /**
     * Batch the decryption factors of the given party.
     *
     * @param l Index of other party.
     */
    public void batch(final int l) {
        B[l] = f[l].expProd(e);
    }

    /**
     * Verify the proof of the given party.
     *
     * @param l Index of other party.
     * @param v Challenge.
     * @return Verdict of verification.
     */
    public boolean verify(final int l, final LargeInteger v) {
        if (!verdicts[l]) {
            return false;
        }

        final PFieldElement pfev = pField.toElement(v);
        return y[l].inv().exp(inverseFactor.mul(pfev)).mul(yp[l]).
            equals(g.exp(k_x[l]))
            && B[l].exp(pfev).mul(Bp[l]).equals(A.exp(k_x[l]));
    }

    /**
     * Free allocated resources.
     */
    public void free() {
        e.free();
    }
}
