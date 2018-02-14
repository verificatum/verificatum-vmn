
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

package com.verificatum.protocol.mixnet;

import java.io.File;

import com.verificatum.protocol.ProtocolBBGen;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.com.BullBoardBasicGen;
import com.verificatum.protocol.elgamal.ProtocolElGamalInterfaceFactory;
import com.verificatum.ui.info.InfoGenerator;


/**
 * Factory for interfaces of an El Gamal protocol.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalInterfaceFactory
    extends ProtocolElGamalInterfaceFactory {

    /**
     * Return the info generator of this factory.
     *
     * @param protocolInfoFile Protocol info file.
     * @return Info generator.
     *
     * @throws ProtocolFormatException If the input is not the name of
     * a file from which a valid bulletin board can be derived.
     */
    @Override
    public InfoGenerator getGenerator(final File protocolInfoFile)
        throws ProtocolFormatException {

        final BullBoardBasicGen bullBoardBasicGen =
            ProtocolBBGen.getBullBoardBasicGen(protocolInfoFile);

        return new MixNetElGamalGen(bullBoardBasicGen);
    }
}
