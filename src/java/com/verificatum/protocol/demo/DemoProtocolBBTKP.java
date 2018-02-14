
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

package com.verificatum.protocol.demo;

import com.verificatum.arithm.PGroup;
import com.verificatum.crypto.CryptoKeyGen;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public abstract class DemoProtocolBBTKP extends ProtocolBBT {

    /**
     * Key generation algorithm.
     */
    protected CryptoKeyGen keygen;

    /**
     * Underlying group.
     */
    protected PGroup pGroup;

    /**
     * Creates a runnable wrapper for the protocol.
     *
     * @param privateInfo Information about this party.
     * @param protocolInfo Information about the protocol executed,
     * including information about other parties.
     * @param ui User interface.
     * @throws Exception If the info instances are malformed.
     */
    public DemoProtocolBBTKP(final PrivateInfo privateInfo,
                             final ProtocolInfo protocolInfo,
                             final UI ui)
        throws Exception {
        super(privateInfo, protocolInfo, ui);

        final String keyGenString = privateInfo.getStringValue("keygen");
        keygen = Marshalizer.unmarshalHexAux_CryptoKeyGen(keyGenString,
                                                          randomSource,
                                                          certainty);

        final String pGroupString = protocolInfo.getStringValue("pgroup");
        pGroup = Marshalizer.unmarshalHexAux_PGroup(pGroupString,
                                                    randomSource,
                                                    certainty);
    }
}
