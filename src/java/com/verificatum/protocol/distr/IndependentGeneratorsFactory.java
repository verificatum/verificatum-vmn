
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

package com.verificatum.protocol.distr;

import com.verificatum.protocol.elgamal.ProtocolElGamal;

/**
 * This is a joint factory class for {@link IndependentGeneratorsI}
 * and {@link IndependentGeneratorsRO}, i.e., it can be instantiated
 * to create instances of one of these classes.
 *
 * @author Douglas Wikstrom
 */
public interface IndependentGeneratorsFactory {

    /**
     * Creates an instance of the factory.
     *
     * @param sid Session identifier of the created instance.
     * @param protocol Protocol which invokes the created instance.
     * @return An instance of the protocol with the given parent
     * protocol and session identifier.
     */
    IndependentGenerators newInstance(String sid,
                                      ProtocolElGamal protocol);
}
