
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

package com.verificatum.protocol.secretsharing;

import com.verificatum.arithm.BiExp;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PRingElement;
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
 * Demonstrates Pedersen's verifiable secret sharing protocol
 * {@link com.verificatum.protocol.secretsharing.Pedersen}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingGenericException"})
public final class DemoPedersen extends DemoProtocolElGamalFactory {

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecPedersen(privateInfo, protocolInfo, ui);
    }

    // public Opt generateOpt(Demo demo) {
    // Opt opt = super.generateOpt(demo);

    // opt.addOption("-pGroup", "pGroup",
    // "Prime order group used in the protocol.");
    // opt.appendToUsageForm(0, "#-pGroup##");

    // return opt;
    // }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        for (int i = 2; i < servers.length; i++) {
            if (!((ExecPedersen) servers[1]).recoveredSecret
                .equals(((ExecPedersen) servers[i]).recoveredSecret)) {
                throw new DemoException("Recovered secrets are not equal!");
            }
        }
    }

    /**
     * Turns {@link Pedersen} into a runnable object.
     */
    static class ExecPedersen extends ProtocolElGamal implements DemoProtocol {

        /**
         * Secret value shared during the execution of the protocol
         * and then used for testing.
         */
        protected PRingElement recoveredSecret;

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
        ExecPedersen(final PrivateInfo privateInfo,
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

                pGroup = new PPGroup(pGroup, 2);

                final BiPRingPGroup biExp = new BiExp(pGroup);
                final HomPRingPGroup hom = biExp.restrict(pGroup.getg());

                final Pedersen ped =
                    new Pedersen("DemoSID",
                                 this,
                                 1,
                                 hom,
                                 plainKeys.getPKeys(),
                                 plainKeys.getSKey(),
                                 rbitlen,
                                 true);
                if (j == 1) {
                    if (!ped.stateOnFile()) {
                        final PRingElement secret =
                            pGroup.getPRing().randomElement(randomSource,
                                                            rbitlen);

                        ped.dealSecret(ui.getLog(), secret);

                        ui.getLog().info("secret = " + secret.toString());
                    }
                } else {
                    ped.receiveShare(ui.getLog());
                }
                recoveredSecret = ped.recover(ui.getLog());

                ui.getLog().info("Recovered secret = "
                                 + recoveredSecret.toString());

                shutdown(ui.getLog());

            } catch (final Exception e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
