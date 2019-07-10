
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElement;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.protocol.hvzk.PoSCTWFactory;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Demonstrates {@link PermutationCommitment}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingGenericException"})
public class DemoPermutationCommitment extends DemoProtocolElGamalFactory {

    /**
     * Creates a root protocol.
     *
     */
    public DemoPermutationCommitment() {
        gen = new PermutationCommitmentGen();
    }

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecPermutationCommitment(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        final ExecPermutationCommitment server1 =
            (ExecPermutationCommitment) servers[1];

        for (int i = 2; i < servers.length; i++) {
            if (!server1.commitment.
                equals(((ExecPermutationCommitment) servers[i]).commitment)) {

                final String e = "Parties have different commitments!";
                throw new DemoException(e);
            }
        }
    }

    /**
     * Turns {@link IndependentGenerator} into a runnable object.
     */
    static class ExecPermutationCommitment extends ProtocolElGamal
        implements DemoProtocol {

        /**
         * Permutation commitment generated during execution and used
         * for testing.
         */
        protected PGroupElementArray commitment;

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
        ExecPermutationCommitment(final PrivateInfo privateInfo,
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

                PGroupElementArray generators;

                if (j == 1) {

                    generators =
                        pGroup.randomElementArray(10, randomSource, rbitlen);

                    ui.getLog().info("Publish demo generators.");
                    bullBoard.publish("Generators",
                                      generators.toByteTree(), ui.getLog());
                } else {

                    final ByteTreeReader reader =
                        bullBoard.waitFor(1, "Generators", ui.getLog());
                    try {
                        generators = pGroup.toElementArray(0, reader);
                    } catch (final ArithmFormatException afe) {
                        throw new DemoError("Failed to read public key!", afe);
                    }
                }

                final File auxsid = getFile("auxsid");

                final PermutationCommitment pc =
                    new PermutationCommitment("DemoSID",
                                              this,
                                              "",
                                              auxsid,
                                              1,
                                              generators,
                                              new PoSCTWFactory());

                pc.precompute(ui.getLog());

                final PRingElement raisedExponent =
                    pGroup.getPRing().randomElement(randomSource, rbitlen);
                pc.generate(ui.getLog(), raisedExponent);

                commitment = pc.getCommitment();

                shutdown(ui.getLog());

            } catch (final Exception e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
