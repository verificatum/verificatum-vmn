
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
