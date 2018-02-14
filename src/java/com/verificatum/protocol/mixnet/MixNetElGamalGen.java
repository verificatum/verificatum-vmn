
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
