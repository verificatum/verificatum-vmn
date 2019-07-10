
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

package com.verificatum.protocol.distr;

import com.verificatum.arithm.BiExp;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.PPGroup;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolBBTKP;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 * Demonstrates the distributed key generation protocol {@link DKG}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingGenericException"})
public class DemoDKG extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecDKG(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {
    }

    /**
     * Turns {@link DKG} into a runnable object.
     */
    static class ExecDKG extends DemoProtocolBBTKP implements DemoProtocol {

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
        ExecDKG(final PrivateInfo privateInfo,
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

                final PPGroup pPGroup = new PPGroup(pGroup, 3);

                final BiPRingPGroup bi = new BiExp(pPGroup);
                final DKG dkg = new DKG("DemoSID",
                                        this,
                                        plainKeys.getPKeys(),
                                        plainKeys.getSKey(),
                                        rbitlen);

                dkg.generate(ui.getLog(), bi, bi.getPGroupDomain().getg());
                dkg.generate(ui.getLog(), bi, bi.getPGroupDomain().getg());

                final StringBuffer sb = new StringBuffer();
                sb.append(dkg.getPublicKey(1));
                for (int i = 2; i <= threshold; i++) {
                    sb.append(',');
                    sb.append(dkg.getPublicKey(i));
                }
                ui.getLog().info("Public keys: " + sb.toString());

                shutdown(ui.getLog());

            } catch (final Exception e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
