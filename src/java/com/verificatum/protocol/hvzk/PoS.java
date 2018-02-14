
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
