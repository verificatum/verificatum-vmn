
/* Copyright 2008-2019 Douglas Wikstrom
 *
 * This file is part of Verificatum Mix-Net (VMN).
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
