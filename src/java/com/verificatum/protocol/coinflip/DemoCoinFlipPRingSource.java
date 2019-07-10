
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
