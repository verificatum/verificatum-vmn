
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

import java.util.Arrays;

import com.verificatum.crypto.CryptoPKey;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Demonstrates the protocol for generating plain keys of a
 * cryptosystem.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingGenericException"})
public class DemoPlainKeys extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecPlainKeys(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        for (int i = 2; i < servers.length; i++) {
            if (!Arrays.equals(((ExecPlainKeys) servers[1]).eppkeys,
                               ((ExecPlainKeys) servers[i]).eppkeys)) {
                throw new DemoException("Arrays of public keys of different "
                                        + "parties differ!");
            }
        }
    }

    /**
     * Turns {@link PlainKeys} into a runnable object.
     */
    static class ExecPlainKeys extends ProtocolElGamal
        implements DemoProtocol {

        /**
         * Keys generated and used for testing.
         */
        public CryptoPKey[] eppkeys;

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
        ExecPlainKeys(final PrivateInfo privateInfo,
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
                plainKeys.generate(ui.getLog());

                eppkeys = plainKeys.getPKeys();

                shutdown(ui.getLog());

            } catch (final Exception e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
