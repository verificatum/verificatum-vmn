
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

import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.com.BullBoardBasicGen;
import com.verificatum.protocol.elgamal.ProtocolElGamalGen;
import com.verificatum.ui.info.InfoException;
import com.verificatum.ui.info.IntField;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Defines the additional information fields and default values that
 * stored in the protocol and private info files used by a mix-net.
 *
 * @author Douglas Wikstrom
 */
public final class MixNetElGamalGen extends ProtocolElGamalGen {

    /**
     * Description of maximal number of ciphertexts field.
     */
    public static final String MAXCIPHS_DESCRIPTION =
        "Maximal number of ciphertexts for which precomputation is "
        + "performed. Pre-computation can still be forced for a different "
        + "number of ciphertexts for a given session "
        + "using the \"-maxciph\" option during pre-computation.";

    /**
     * Description of default width field.
     */
    public static final String WIDTH_DESCRIPTION =
        "Default width of ciphertexts processed by the mix-net. A different "
        + "width can still be forced for a given session by using the "
        + "\"-width\" option.";

    /**
     * Creates an instance for a given implementation of a bulletin
     * board.
     *
     * @param bbbg Adds the values needed by the particular
     * instantiation of bulletin board used.
     */
    public MixNetElGamalGen(final BullBoardBasicGen bbbg) {
        super(bbbg);
    }

    /**
     * Creates an instance using the default bulletin board.
     */
    public MixNetElGamalGen() {
        super();
    }

    @Override
    public void addProtocolInfo(final ProtocolInfo pri) {
        super.addProtocolInfo(pri);

        pri.addInfoFields(new IntField(MixNetElGamal.WIDTH,
                                       WIDTH_DESCRIPTION, 1, 1, 1, null));
        pri.addInfoFields(new IntField(MixNetElGamal.MAXCIPH,
                                       MAXCIPHS_DESCRIPTION, 1, 1, 0, null));
    }

    @Override
    public void addDefault(final ProtocolInfo pi) {
        super.addDefault(pi);
        try {
            pi.addValue(MixNetElGamal.WIDTH, 1);
            pi.addValue(MixNetElGamal.MAXCIPH, 0);
        } catch (InfoException ie) {
            throw new ProtocolError("Failed to add default value!", ie);
        }
    }
}
