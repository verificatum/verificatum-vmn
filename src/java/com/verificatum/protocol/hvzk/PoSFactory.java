
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

import java.io.File;

import com.verificatum.protocol.elgamal.ProtocolElGamal;


/**
 * Factory for instances implementing {@link PoS}.
 *
 * @author Douglas Wikstrom
 */
public interface PoSFactory {

    /**
     * Returns a new instance with the given session identifier and
     * parent protocol.
     *
     * @param sid Session identifier.
     * @param protocol Parent protocol.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * com.verificatum.protocol.Protocol#deleteState()} is called.
     * @return Instance of a proof of a shuffle.
     */
    PoS newPoS(String sid, ProtocolElGamal protocol, String rosid, File nizkp);
}
