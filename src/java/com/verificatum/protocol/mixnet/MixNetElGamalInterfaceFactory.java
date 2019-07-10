
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
