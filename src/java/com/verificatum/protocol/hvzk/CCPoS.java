
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

import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.ui.Log;

/**
 * Interface for a commitment-consistent proof of a shuffle.
 *
 * @author Douglas Wikstrom
 */
public interface CCPoS {

    /**
     * Execute prover.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param h Independent generators.
     * @param u Permutation commitment.
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @param r Commitment exponents.
     * @param pi Permutation.
     * @param s Random exponents used to process ciphertexts.
     */
    void prove(Log log,
               PGroupElement g,
               PGroupElementArray h,
               PGroupElementArray u,
               PGroupElement pkey,
               PGroupElementArray w,
               PGroupElementArray wp,
               PRingElementArray r,
               Permutation pi,
               PRingElementArray s);

    /**
     * Execute verifier.
     *
     * @param log Logging context.
     * @param l Index of prover.
     * @param g Standard generator.
     * @param h Independent generators.
     * @param u Permutation commitment.
     * @param pkey Public key used to re-encrypt.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @param raisedu Permutation commitment raised to a secret
     * exponent.
     * @param raisedh Independent generators raised to a secret
     * exponent.
     * @param raisedExponent Secret exponent.
     * @return Verdict about the proof.
     */
    boolean verify(Log log,
                   int l,
                   PGroupElement g,
                   PGroupElementArray h,
                   PGroupElementArray u,
                   PGroupElement pkey,
                   PGroupElementArray w,
                   PGroupElementArray wp,
                   PGroupElementArray raisedu,
                   PGroupElementArray raisedh,
                   PRingElement raisedExponent);
}
