
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
