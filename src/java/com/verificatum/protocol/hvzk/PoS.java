
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
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.ui.Log;

/**
 * Interface for a proof of a shuffle.
 *
 * @author Douglas Wikstrom
 */
public interface PoS {

    /**
     * Performs precomputation of prover.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param h Independent generators.
     * @param pi Permutation.
     */
    void precompute(Log log,
                    PGroupElement g,
                    PGroupElementArray h,
                    Permutation pi);

    /**
     * Execute prover.
     *
     * @param log Logging context.
     * @param pkey Public key used to construct the homomorphism.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @param s Random exponents used to process ciphertexts.
     */
    void prove(Log log,
               PGroupElement pkey,
               PGroupElementArray w,
               PGroupElementArray wp,
               PRingElementArray s);

    /**
     * Performs precomputation of the verifier.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param h Independent generators.
     */
    void precompute(Log log, PGroupElement g, PGroupElementArray h);

    /**
     * Execute verifier.
     *
     * @param log Logging context.
     * @param l Index of prover.
     * @param pkey Public key used to construct the homomorphism.
     * @param w List of ciphertexts.
     * @param wp List of ciphertexts.
     * @return Verdict about the proof.
     */
    boolean verify(Log log,
                   int l,
                   PGroupElement pkey,
                   PGroupElementArray w,
                   PGroupElementArray wp);

    /**
     * Releases resources allocated by this instance.
     */
    void free();
}
