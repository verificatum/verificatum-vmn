
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
 * This is a factory class for {@link IndependentGeneratorsRO}, i.e.,
 * it can be instantiated to create instances of this class.
 *
 * @author Douglas Wikstrom
 */
public final class IndependentGeneratorsROFactory
    implements IndependentGeneratorsFactory {

    @Override
    public IndependentGenerators
        newInstance(final String sid, final ProtocolElGamal protocol) {
        return new IndependentGeneratorsRO(sid,
                                           protocol.getROHashfunction(),
                                           protocol.getGlobalPrefix(),
                                           protocol.getStatDist());
    }
}
