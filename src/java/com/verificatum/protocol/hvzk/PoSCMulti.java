
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
 * Interface for a round of proofs of shuffles.
 *
 * @author Douglas Wikstrom
 */
public interface PoSCMulti {

    /**
     * Execute proofs.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param generators Independent generators.
     * @param permutationCommitments Permutation commitment.
     * @return Array of verdicts.
     */
    boolean[] execute(Log log,
                      PGroupElement g,
                      PGroupElementArray generators,
                      PGroupElementArray[] permutationCommitments);

    /**
     * Execute proofs.
     *
     * @param log Logging context.
     * @param g Standard generator.
     * @param generators Independent generators.
     * @param permutationCommitments Permutation commitment.
     * @param commitmentExponents Commitment exponents.
     * @param permutation Permutation.
     * @return Array of verdicts.
     */
    boolean[] execute(Log log,
                      PGroupElement g,
                      PGroupElementArray generators,
                      PGroupElementArray[] permutationCommitments,
                      PRingElementArray commitmentExponents,
                      Permutation permutation);
}
