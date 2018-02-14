
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

package com.verificatum.protocol.elgamal;

import java.io.File;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Demonstrates {@link DistrElGamal}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingThrowable"})
public class DemoDistrElGamal extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecDistrElGamal(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        final ExecDistrElGamal[] srvs = new ExecDistrElGamal[servers.length];

        for (int i = 1; i < servers.length; i++) {
            srvs[i] = (ExecDistrElGamal) servers[i];
        }

        for (int i = 2; i < servers.length; i++) {
            if (!srvs[1].jointPublicKey.equals(srvs[i].jointPublicKey)) {
                throw new DemoException("Some parties have distinct joint "
                                        + "public keys!");
            }
        }
    }

    /**
     * Turns {@link IndependentGenerator} into a runnable object.
     */
    static class ExecDistrElGamal extends DistrElGamal
        implements DemoProtocol {

        /**
         * Joint public key generated during protocol execution and
         * used for testing.
         */
        protected PGroupElement jointPublicKey;

        /**
         * Plaintext encrypted during execution and used for testing.
         */
        protected PGroupElementArray plaintexts;

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
        ExecDistrElGamal(final PrivateInfo privateInfo,
                         final ProtocolInfo protocolInfo,
                         final UI ui)
            throws Exception {
            super(privateInfo, protocolInfo, ui);
        }

        @Override
        public void run() {
            try {

                final int width = 1;

                startServers();

                setup(ui.getLog());
                generatePublicKey(ui.getLog());

                jointPublicKey = getWideFullPublicKey(width);

                final PGroupElement uJointPublicKey =
                    ((PPGroupElement) jointPublicKey).project(0);
                final PGroupElement vJointPublicKey =
                    ((PPGroupElement) jointPublicKey).project(1);

                final PGroup pGroupInner = uJointPublicKey.getPGroup();
                final PRing pRing = pGroupInner.getPRing();


                final PGroupElement[] plaintextArray = new PGroupElement[10];
                for (int i = 0; i < plaintextArray.length; i++) {
                    plaintextArray[i] = pGroupInner.getg().exp(i);
                }
                plaintexts = pGroupInner.toElementArray(plaintextArray);

                PGroupElementArray ciphertexts = null;

                if (j == 1) {
                    final PRingElementArray r =
                        pRing.randomElementArray(plaintexts.size(),
                                                 randomSource,
                                                 rbitlen);

                    final PGroupElementArray u = uJointPublicKey.exp(r);
                    final PGroupElementArray t = vJointPublicKey.exp(r);
                    final PGroupElementArray v = plaintexts.mul(t);

                    t.free();

                    ciphertexts =
                        ((PPGroup) jointPublicKey.getPGroup()).product(u, v);

                    ui.getLog().info("Publish demo ciphertexts.");
                    bullBoard.publish("Ciphertexts",
                                      ciphertexts.toByteTree(), ui.getLog());

                } else {

                    final ByteTreeReader ciphertextsReader =
                        bullBoard.waitFor(1, "Ciphertexts", ui.getLog());

                    try {
                        ciphertexts = jointPublicKey.getPGroup().
                            toElementArray(0, ciphertextsReader);
                    } catch (final ArithmFormatException afe) {
                        throw new DemoError("Failed to read ciphertexts!", afe);
                    }
                }

                final File nizkp = getFile("nizkp");

                final DistrElGamalSession session = getSession("first", nizkp);

                session.decrypt(ui.getLog(), ciphertexts);

                shutdown(ui.getLog());

            } catch (final Throwable e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
