
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

package com.verificatum.protocol.elgamal;

import java.io.File;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.crypto.RandomSource;


/**
 * Interface of an El Gamal mix-net with the ability to generate demo
 * ciphertexts.
 *
 * @author Douglas Wikstrom
 */
public interface ProtocolElGamalInterfaceDemo {

    /**
     * Generates the given number of ciphertexts.
     *
     * @param fullPublicKey Full public key.
     * @param noCiphs Number of ciphertexts to generate.
     * @param outputFile Destination of generated ciphertexts.
     * @param randomSource Source of randomness.
     */
    void demoCiphertexts(PGroupElement fullPublicKey,
                         int noCiphs,
                         File outputFile,
                         RandomSource randomSource);
}
