
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

package com.verificatum.protocol.hvzk;

import java.io.File;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.arithm.Permutation;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
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
 * Demonstrates the execution of a {@link PoSCTW}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingThrowable"})
public class DemoPoSCTW extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecPoSCTW(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        for (int i = 2; i < servers.length; i++) {
            if (((ExecPoSCTW) servers[1]).verdict
                != ((ExecPoSCTW) servers[i]).verdict) {
                throw new DemoException("Verdicts of parties differ!");
            }
        }
    }

    /**
     * Turns {@link PoSCTW} into a runnable object.
     */
    static class ExecPoSCTW extends ProtocolElGamal implements DemoProtocol {

        /**
         * Verdict of the verifier after the execution of the protocol.
         */
        protected boolean verdict;

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
        ExecPoSCTW(final PrivateInfo privateInfo,
                   final ProtocolInfo protocolInfo,
                   final UI ui)
            throws Exception {
            super(privateInfo, protocolInfo, ui);
        }

        @Override
        public void run() {
            try {

                startServers();

                setup(ui.getLog());

                final int size = 5;

                final PlainKeys plainKeys =
                    new PlainKeys("DemoSID", this, keygen, rbitlen);
                plainKeys.generate(ui.getLog());

                //pGroup = new PPGroup(pGroup, 3);

                final PGroupElement g = pGroup.getg();
                PGroupElementArray h = null;
                PGroupElementArray u = null;

                final File nizkp = getFile("nizkp");

                if (j == 1) {

                    h = g.exp(pGroup.getPRing().randomElementArray(size,
                                                                   randomSource,
                                                                   rbitlen));

                    final PRingElementArray r =
                        pGroup.getPRing().randomElementArray(size,
                                                             randomSource,
                                                             rbitlen);
                    u = g.exp(r).mul(h);
                    final Permutation pi =
                        Permutation.random(size, randomSource, rbitlen);

                    u = u.permute(pi);

                    final ByteTreeContainer bt =
                        new ByteTreeContainer(h.toByteTree(), u.toByteTree());


                    ui.getLog().info("Publish data.");
                    bullBoard.publish("Data", bt, ui.getLog());

                    final PoSCTW P = new PoSCTW("", this, "rosid", nizkp);
                    P.prove(ui.getLog(), g, h, u, r, pi);

                    verdict = true;

                } else {

                    final ByteTreeReader dataReader =
                        bullBoard.waitFor(1, "Data", ui.getLog());

                    try {
                        h = pGroup.toElementArray(0, dataReader.getNextChild());
                        u = pGroup.toElementArray(0, dataReader.getNextChild());
                    } catch (final ArithmFormatException afe) {
                        throw new DemoError("Failed to read data!", afe);
                    }

                    final PoSCTW V = new PoSCTW("", this, "rosid", nizkp);
                    verdict = V.verify(ui.getLog(), 1, g, h, u);
                }

                shutdown(ui.getLog());

            } catch (final Throwable e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
