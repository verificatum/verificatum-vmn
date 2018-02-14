
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

package com.verificatum.protocol.coinflip;

import java.util.Arrays;

import com.verificatum.arithm.PRingElement;
import com.verificatum.eio.Hex;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.protocol.distr.PlainKeys;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Demonstrates a source of jointly generated random coins {@link
 * CoinFlipPRingSource}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingGenericException"})
public final class DemoCoinFlipPRingSource extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecCoinFlipPRingSource(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        for (int i = 2; i < servers.length; i++) {
            if (!Arrays.equals(((ExecCoinFlipPRingSource) servers[1]).elems,
                               ((ExecCoinFlipPRingSource) servers[i]).elems)) {
                throw new DemoException("Arrays of coins of different "
                                        + "parties differ!");
            }

            for (int l = 0; l < 5; l++) {

                final byte[] bytes1 =
                    ((ExecCoinFlipPRingSource) servers[1]).bits[l];
                final byte[] bytesi =
                    ((ExecCoinFlipPRingSource) servers[i]).bits[l];
                if (!Arrays.equals(bytes1, bytesi)) {
                    throw new DemoException("Arrays of bits of different "
                                            + "parties differ!");
                }
            }
        }
    }

    /**
     * Turns {@link CoinFlipPRingSource} into a runnable object.
     */
    static class ExecCoinFlipPRingSource
        extends ProtocolElGamal
        implements DemoProtocol {

        /**
         * Elements used during execution and testing.
         */
        protected PRingElement[] elems;

        /**
         * Bits used during execution and testing.
         */
        protected byte[][] bits;

        /**
         * Creates a runnable wrapper for the protocol.
         *
         * @param privateInfo Information about this party.
         * @param protocolInfo Information about the protocol
         * executed, including information about other
         * parties.
         * @param ui User interface.
         * @throws Exception If the info instances are malformed.
         */
        ExecCoinFlipPRingSource(final PrivateInfo privateInfo,
                                final ProtocolInfo protocolInfo,
                                final UI ui)
            throws Exception {
            super(privateInfo, protocolInfo, ui);
        }

        @Override
        public void run() {
            try {

                startServers();

                final PlainKeys plainKeys =
                    new PlainKeys("DemoSID", this, keygen, rbitlen);
                plainKeys.generate(ui.getLog());

                final CoinFlipPRingSource coins =
                    new CoinFlipPRingSource("DemoSID",
                                            this,
                                            pGroup.getg().exp(7),
                                            plainKeys.getPKeys(),
                                            plainKeys.getSKey(),
                                            rbitlen);

                coins.prepareCoins(ui.getLog(), 3);

                elems = new PRingElement[5];

                for (int i = 0; i < 5; i++) {
                    elems[i] = coins.getCoin(ui.getLog());
                    ui.getLog().info("coin = " + elems[i].toString());
                }

                bits = new byte[5][];

                for (int l = 1; l < 4; l++) {
                    bits[l] = coins.getCoinBytes(ui.getLog(), l * 50, rbitlen);
                    ui.getLog().info("coin = " + Hex.toHexString(bits[l]));
                }

                shutdown(ui.getLog());

            } catch (final Exception e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
