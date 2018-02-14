
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PFieldElementArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.protocol.ProtocolError;

/**
 * Implements the basic functionality of Wikstrom's
 * commitment-consistent proof of a shuffle.
 *
 * <p>
 *
 * For clarity, each method is labeled BOTH, PROVER, or VERIFIER
 * depending on which parties normally call the method.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.VariableNamingConventions",
                   "PMD.MethodNamingConventions",
                   "PMD.SingletonClassReturningNewInstanceRule"})
public final class CCPoSBasicW {

    /**
     * Size of the set that is permuted.
     */
    int size;

    /**
     * Bit length of the challenge.
     */
    int vbitlen;

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
     * Underlying group.
     */
    PGroup pGroup;

    /**
     * Ring associated with the commitment group.
     */
    PRing pRing;

    /**
     * Field associated with the ring.
     */
    PField pField;

    // ################### Instance and witness ###################

    /**
     * Standard generator of the group.
     */
    PGroupElement g;

    /**
     * Array of "independent" generators.
     */
    PGroupElementArray h;

    /**
     * Commitment of a permutation.
     */
    PGroupElementArray u;

    /**
     * Aggregate of permutation commitments.
     */
    PGroupElement A;

    /**
     * Aggregate of input ciphertexts.
     */
    PGroupElement B;

    /**
     * Aggregate of input ciphertexts and commitments.
     */
    PGroupElement AB;

    /**
     * Random exponents used to form the permutation commitment.
     */
    PRingElementArray r;

    /**
     * Permutation committed to.
     */
    Permutation pi;

    /**
     * Public key used to re-encrypt.
     */
    PPGroupElement pkey;

    /**
     * Input ciphertexts.
     */
    PGroupElementArray w;

    /**
     * Output ciphertexts.
     */
    PGroupElementArray wp;

    /**
     * Random exponents used to form the output ciphertexts.
     */
    PRingElementArray s;

    // ################# Message 1 (verifier) #####################

    /**
     * Vector of random exponents.
     */
    PFieldElementArray e;

    // ################# Message 2 (prover) #######################

    /**
     * Proof commitment.
     */
    PGroupElement Ap;

    /**
     * Proof commitment.
     */
    PGroupElement Bp;

    // ########### Secret values for bridging commitment #######

    /**
     * Inversely permuted random vector. (This is denoted e' in the
     * comments below.)
     */
    PFieldElementArray ipe;

    // ######### Randomizers and blinders of the prover ########

    /**
     * Randomizer for inner product of r and e'.
     */
    PRingElement alpha;

    /**
     * Randomizer for inverse permuted batching vector.
     */
    PFieldElementArray epsilon;

    /**
     * Randomizer for inner product of s and e.
     */
    PRingElement beta;

    // ################## Message 3 (Verifier) ##################

    /**
     * Challenge from the verifier.
     */
    PFieldElement v;

    // ################## Message 4 (Prover) ##################

    /**
     * Reply for inner product of r and e'.
     */
    PRingElement k_A;

    /**
     * Reply inner product of s and e.
     */
    PRingElement k_B;

    /**
     * Reply for the inverse permuted random vector.
     */
    PFieldElementArray k_E;

    /**
     * BOTH: Constructor to instantiate the protocol.
     *
     * @param vbitlen Bit length of the challenge.
     * @param ebitlen Bit length of each component in random
     * vector.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param prg PRG used to expands seeds for batching.
     */
    public CCPoSBasicW(final int vbitlen,
                       final int ebitlen,
                       final int rbitlen,
                       final PRG prg) {
        this.vbitlen = vbitlen;
        this.ebitlen = ebitlen;
        this.rbitlen = rbitlen;
        this.prg = prg;
    }

    /**
     * VERIFIER: Initializes the instance.
     *
     * @param g Standard generator used in permutation commitments.
     * @param h "Independent" generators used in permutation
     * commitments.
     * @param u Permutation commitment.
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     */
    public void setInstance(final PGroupElement g,
                            final PGroupElementArray h,
                            final PGroupElementArray u,
                            final PGroupElement pkey,
                            final PGroupElementArray w,
                            final PGroupElementArray wp) {
        this.g = g;
        this.h = h;
        this.u = u;

        this.pkey = (PPGroupElement) pkey;
        this.w = w;
        this.wp = wp;

        this.r = null;
        this.pi = null;
        this.s = null;

        this.size = h.size();
        this.pGroup = g.getPGroup();
        this.pRing = pGroup.getPRing();
        this.pField = pRing.getPField();
    }

    /**
     * PROVER: Initializes the instance.
     *
     * @param g Standard generator used in permutation commitments.
     * @param h "Independent" generators used in permutation
     * commitments.
     * @param u Permutation commitment.
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @param r Random exponents used to form the permutation
     * commitment.
     * @param pi Permutation committed to.
     * @param s Random exponents used to process ciphertexts.
     */
    public void setInstance(final PGroupElement g,
                            final PGroupElementArray h,
                            final PGroupElementArray u,
                            final PGroupElement pkey,
                            final PGroupElementArray w,
                            final PGroupElementArray wp,
                            final PRingElementArray r,
                            final Permutation pi,
                            final PRingElementArray s) {
        setInstance(g, h, u, pkey, w, wp);
        this.r = r;
        this.pi = pi;
        this.s = s;
    }

    /**
     * BOTH: Extracts the random vector from a seed. This is useful
     * when the honest verifier is replaced by a coin tossing protocol
     * or when this protocol is used as a subprotocol.
     *
     * @param prgSeed Seed to the pseudorandom generator used to
     * extract the random vector.
     */
    public void setBatchVector(final byte[] prgSeed) {
        prg.setSeed(prgSeed);
        final LargeIntegerArray lia =
            LargeIntegerArray.random(size, ebitlen, prg);
        this.e = pField.unsafeToElementArray(lia);
    }

    /**
     * PROVER: Generates the commitment of the prover.
     *
     * @param prgSeed Seed used to extract the random vector.
     * @param randomSource Source of random bits.
     * @return Representation of the commitments.
     */
    public ByteTreeBasic commit(final byte[] prgSeed,
                                final RandomSource randomSource) {

        setBatchVector(prgSeed);

        // ################# Permuted Batching Vector #############

        ipe = e.permute(pi.inv());

        // ################# Proof Commitments ####################

        // During verification, the verifier computes:
        //
        // A = \prod u_i^{e_i} (1)
        //
        // and requires that it equals:
        //
        // g^{<r,e'>} * \prod h_i^{e_i'} (2)
        //
        // We must show that we can open (1) as (2). For that purpose
        // we generate randomizers.

        alpha = pRing.randomElement(randomSource, rbitlen);

        // The bit length of each component of e' is bounded. Thus,
        // we can sample its randomizers as follows.

        final int epsilonBitLength = ebitlen + vbitlen + rbitlen;

        final LargeIntegerArray epsilonIntegers =
            LargeIntegerArray.random(size, epsilonBitLength, randomSource);
        epsilon = pField.toElementArray(epsilonIntegers);
        epsilonIntegers.free();

        // Next we compute the corresponding blinder.

        Ap = g.exp(alpha).mul(h.expProd(epsilon));

        // We must show that we can open B = \prod w_i^{e_i} as
        //
        // B = Enc_pk(-b)\prod (w_i')^{e_i'}
        //
        // where b=<s,e>.
        //
        final PRing ciphPRing = pkey.project(0).getPGroup().getPRing();
        beta = ciphPRing.randomElement(randomSource, rbitlen);

        Bp = pkey.exp(beta.neg()).mul(wp.expProd(epsilon));

        // ################### Byte tree ##########################

        return new ByteTreeContainer(Ap.toByteTree(), Bp.toByteTree());
    }

    /**
     * VERIFIER: Sets the commitment.
     *
     * @param btr Commitment from the prover.
     * @return Representation of the commitments.
     */
    public ByteTreeBasic setCommitment(final ByteTreeReader btr) {

        final PGroup ciphPGroup = pkey.getPGroup();

        boolean malformed = false;
        try {

            Ap = pGroup.toElement(btr.getNextChild());
            Bp = ciphPGroup.toElement(btr.getNextChild());

        } catch (final EIOException eioe) {
            malformed = true;
        } catch (final ArithmFormatException afe) {
            malformed = true;
        }

        // If anything is malformed we set it to suitable
        // predetermined trivial value.
        if (malformed) {

            Ap = pGroup.getONE();
            Bp = ciphPGroup.getONE();
        }

        return new ByteTreeContainer(Ap.toByteTree(), Bp.toByteTree());
    }

    /**
     * Returns the bit length of challenges.
     *
     * @return Bit length of challenge.
     */
    public int getVbitlen() {
        return vbitlen;
    }

    /**
     * VERIFIER: Sets the challenge. This is useful if the challenge
     * is generated jointly.
     *
     * @param integerChallenge Challenge of verifier.
     */
    public void setChallenge(final LargeInteger integerChallenge) {
        if (!(0 <= integerChallenge.compareTo(LargeInteger.ZERO)
              && integerChallenge.bitLength() <= vbitlen)) {

            throw new ProtocolError("Malformed challenge!");
        }
        this.v = pField.toElement(integerChallenge);
    }

    /**
     * Computes the reply of the prover to the given challenge, i.e.,
     * the second message of the prover.
     *
     * @param integerChallenge Challenge of verifier.
     * @return Reply of prover.
     */
    public ByteTreeBasic reply(final LargeInteger integerChallenge) {

        setChallenge(integerChallenge);

        // Initialize the special exponents.
        final PRingElement a = r.innerProduct(ipe);
        final PRingElement b = s.innerProduct(e);

        // Compute the replies as:
        //
        // k_A = va + \alpha
        // k_B = vb + \beta
        // k_{E,i} = ve_i' + \epsilon_i
        //
        k_A = a.mulAdd(v, alpha);
        k_B = b.mulAdd(v, beta);
        k_E = (PFieldElementArray) ipe.mulAdd(v, epsilon);

        final ByteTreeContainer reply =
            new ByteTreeContainer(k_A.toByteTree(),
                                  k_B.toByteTree(),
                                  k_E.toByteTree());
        return reply;
    }

    /**
     * VERIFIER: Compute A and B.
     *
     * @param raisedu If pre-computation is used this is a vector that
     * speeds up computations.
     */
    public void computeAB(final PGroupElementArray raisedu) {

        if (raisedu == null) {

            A = u.expProd(e);
            B = w.expProd(e);

        } else {

            final PGroupElementArray tmp = w.mul(raisedu);
            AB = tmp.expProd(e);
            tmp.free();
        }
    }

    /**
     * VERIFIER: Verifies the reply of the prover and outputs true or
     * false depending on if the reply was accepted or not.
     *
     * @param btr Reply of the prover.
     * @param raisedh Independent generators raised to the secret
     * exponent.
     * @param raisedExponent Secret exponent.
     * @return <code>true</code> if the reply is accepted and
     *         <code>false</code> otherwise.
     */
    public boolean verify(final ByteTreeReader btr,
                          final PGroupElementArray raisedh,
                          final PRingElement raisedExponent) {

        final PRing ciphPRing = pkey.project(0).getPGroup().getPRing();

        // Read and parse replies.
        boolean malformed = false;
        try {

            k_A = pRing.toElement(btr.getNextChild());
            k_B = ciphPRing.toElement(btr.getNextChild());
            k_E = pField.toElementArray(size, btr.getNextChild());

        } catch (final EIOException eio) {
            malformed = true;
        } catch (final ArithmFormatException afe) {
            malformed = true;
        }
        if (malformed) {
            k_A = pRing.getZERO();
            k_B = ciphPRing.getZERO();
            k_E = (PFieldElementArray) pField.toElementArray(size,
                                                             pField.getZERO());
            return false;
        }

        // Assume prover makes us accept.
        boolean verdict = true;

        // Verify that prover knows a=<r,e'> and e' such that:
        //
        // A = \prod u_i^{e_i} = g^a * \prod h_i^{e_i'}
        //

        if (raisedExponent == null
            && !A.expMul(v, Ap).equals(g.exp(k_A).mul(h.expProd(k_E)))) {
            verdict = false;
        }

        if (verdict) {

            // Verify that the prover knows b = <s,e> such that
            //
            // B = \prod w_i^{e_i} = \phi(-b)\prod (w_i')^{e_i'}
            //
            if (raisedExponent == null) {
                if (!B.expMul(v, Bp).
                    equals(pkey.exp(k_B.neg()).mul(wp.expProd(k_E)))) {

                    verdict = false;
                }
            } else {
                final PGroupElementArray wp_mul_raisedh = wp.mul(raisedh);

                if (!AB.expMul(v, Bp.mul(Ap.exp(raisedExponent))).
                    equals(pkey.exp(k_B.neg()).mul(wp_mul_raisedh.expProd(k_E))
                           .mul(g.exp(k_A.mul(raisedExponent))))) {
                    verdict = false;
                }
                wp_mul_raisedh.free();
            }
        }

        return verdict;
    }

    /**
     * VERIFIER: Returns the reply that must already have been
     * processed.
     *
     * @return Reply processed by the verifier.
     */
    public ByteTreeBasic getReply() {
        return new ByteTreeContainer(k_A.toByteTree(), k_B.toByteTree(),
                                     k_E.toByteTree());
    }

    /**
     * Releases any resources allocated by this instance.
     */
    public void free() {

        if (e != null) {
            e.free();
        }
        if (ipe != null) {
            ipe.free();
        }
        if (epsilon != null) {
            epsilon.free();
        }
        if (k_E != null) {
            k_E.free();
        }
    }
}
