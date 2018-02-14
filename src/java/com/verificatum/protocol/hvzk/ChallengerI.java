
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

import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.protocol.coinflip.CoinFlipPRingSource;
import com.verificatum.ui.Log;

/**
 * Container class for a coin-flipping functionality used to generate
 * challenges for public coin protocols.
 *
 * @author Douglas Wikstrom
 */
public final class ChallengerI implements Challenger {

    /**
     * Source of jointly generated random coins.
     */
    CoinFlipPRingSource coins;

    /**
     * Creates an instance which generates challenges using the given
     * source of jointly generated random coins.
     *
     * @param coins Source of jointly generated random coins.
     */
    public ChallengerI(final CoinFlipPRingSource coins) {
        this.coins = coins;
    }

    // Documented in Challenger.java

    @Override
    public byte[] challenge(final Log log, final ByteTreeBasic data,
                            final int vbitlen, final int rbitlen) {

        log.info("Generate bits jointly.");
        final Log tempLog = log.newChildLog();

        return coins.getCoinBytes(tempLog, vbitlen, rbitlen);
    }
}
