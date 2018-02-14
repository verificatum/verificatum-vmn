
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
 * Interface for a proof of a shuffle of commitments.
 *
 * @author Douglas Wikstrom
 */
public interface PoSC {

    /**
     * Execute prover.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param h Independent generators.
     * @param u Permutation commitment.
     * @param r Commitment exponents.
     * @param pi Permutation.
     */
    void prove(Log log,
               PGroupElement g,
               PGroupElementArray h,
               PGroupElementArray u,
               PRingElementArray r,
               Permutation pi);

    /**
     * Execute verifier.
     *
     * @param log Logging context.
     * @param l Index of prover.
     * @param g Standard generator.
     * @param h Independent generators.
     * @param u Permutation commitment.
     * @return Verdict about the proof.
     */
    boolean verify(Log log,
                   int l,
                   PGroupElement g,
                   PGroupElementArray h,
                   PGroupElementArray u);
}
