
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.demo.DemoError;
import com.verificatum.protocol.demo.DemoException;
import com.verificatum.protocol.demo.DemoProtocol;
import com.verificatum.protocol.demo.DemoProtocolElGamalFactory;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 * Demonstrates {@link ShufflerElGamal}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings({"PMD.SignatureDeclareThrowsException",
                   "PMD.AvoidCatchingThrowable"})
public class DemoShufflerElGamal extends DemoProtocolElGamalFactory {

    /**
     * Creates a root protocol.
     *
     */
    public DemoShufflerElGamal() {
        gen = new ShufflerElGamalGen();
    }

    // These methods are documented in DemoProtocolFactory.java.

    @Override
    public DemoProtocol newProtocol(final PrivateInfo privateInfo,
                                    final ProtocolInfo protocolInfo,
                                    final UI ui)
        throws Exception {
        return new ExecShufflerElGamal(privateInfo, protocolInfo, ui);
    }

    @Override
    public void verify(final DemoProtocol... servers) throws Exception {

        final ExecShufflerElGamal server = (ExecShufflerElGamal) servers[1];

        for (int l = 0; l < 4; l++) {
            if (server.plaintexts[l].equals(server.plaintextsOut[l])) {
                throw new DemoException("Shuffle modified plaintexts!");
            }
        }
    }

    /**
     * Turns {@link IndependentGenerator} into a runnable object.
     */
    static class ExecShufflerElGamal extends ShufflerElGamal
        implements DemoProtocol {

        /**
         * Plaintexts that are encrypted and shuffled during the
         * execution of the protocol.
         */
        protected PGroupElementArray[] plaintexts;

        /**
         * Output plaintexts.
         */
        protected PGroupElementArray[] plaintextsOut;

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
        ExecShufflerElGamal(final PrivateInfo privateInfo,
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

                plaintexts = new PGroupElementArray[4];
                plaintextsOut = new PGroupElementArray[4];

                final PRing pRing = pGroup.getPRing();
                final PPGroup pkPGroup = new PPGroup(pGroup, 2);

                PRingElement x = null;
                if (j == 1) {

                    // Generate and publish public key.
                    x = pRing.randomElement(randomSource, rbitlen);
                    final PGroupElement y = pGroup.getg().exp(x);
                    setPublicKey(pkPGroup.product(pGroup.getg(), y));

                    ui.getLog().info("Publish demo public key.");
                    bullBoard.publish("PublicKey",
                                      publicKey.toByteTree(), ui.getLog());
                } else {

                    // Read public key.
                    final ByteTreeReader publicKeyReader =
                        bullBoard.waitFor(1, "PublicKey", ui.getLog());

                    try {
                        setPublicKey(pkPGroup.toElement(publicKeyReader));
                    } catch (final ArithmFormatException afe) {
                        throw new DemoError("Failed to read public key!", afe);
                    } finally {
                        publicKeyReader.close();
                    }
                }

                // This executes tests with width 1 and 2 and
                // with/without pre-computation.
                for (int l = 0; l < 4; l++) {

                    final int width = l + 1;

                    final PGroup plainPGroup = getPlainPGroup(pGroup, width);
                    final PRing plainPRing = plainPGroup.getPRing();

                    final PPGroup ciphPGroup = getCiphPGroup(pGroup, width);

                    PPGroupElement widePublicKey;

                    getFile("nizkp");

                    PGroupElementArray ciphertexts;
                    ShufflerElGamalSession session;

                    if (j == 1) {

                        // Generate plaintexts.
                        final PGroupElement[] plaintextArray =
                            new PGroupElement[10];
                        for (int i = 0; i < plaintextArray.length; i++) {
                            plaintextArray[i] = plainPGroup.getg().exp(i);
                        }
                        plaintexts[l] =
                            plainPGroup.toElementArray(plaintextArray);

                        // Generate ciphertexts.
                        final PRingElementArray r =
                            plainPRing.randomElementArray(10,
                                                          randomSource,
                                                          rbitlen);

                        widePublicKey =
                            ProtocolElGamal.getWidePublicKey(publicKey, width);

                        final PGroupElementArray u =
                            widePublicKey.project(0).exp(r);
                        final PGroupElementArray t =
                            widePublicKey.project(1).exp(r);
                        final PGroupElementArray v = t.mul(plaintexts[l]);
                        t.free();

                        ciphertexts = ciphPGroup.product(u, v);

                        // Publish ciphertexts.
                        ui.getLog().info("Publish demo ciphertexts.");
                        bullBoard.publish("Ciphertexts" + l,
                                          ciphertexts.toByteTree(),
                                          ui.getLog());

                        session = getSession("mysid" + l, nizkp);

                        PPGroupElementArray ciphertextsOut;
                        if (l < 2) {
                            ciphertextsOut =
                                (PPGroupElementArray)
                                session.shuffle(ui.getLog(),
                                                width,
                                                ciphertexts);
                        } else {
                            session.precomp(ui.getLog(), width, 15);
                            ciphertextsOut =
                                (PPGroupElementArray)
                                session.committedShuffle(ui.getLog(),
                                                         width,
                                                         ciphertexts);
                        }

                        final PGroupElementArray decryptionFactors =
                            ciphertextsOut.project(0).exp(x);

                        plaintextsOut[l] =
                            ciphertextsOut.project(1).mul(decryptionFactors);

                    } else {

                        // Read ciphertexts.
                        final ByteTreeReader ciphertextsReader =
                            bullBoard.waitFor(1, "Ciphertexts" + l,
                                              ui.getLog());

                        try {
                            ciphertexts =
                                ciphPGroup.toElementArray(0, ciphertextsReader);
                        } catch (final ArithmFormatException afe) {
                            throw new DemoError("Failed to read ciphertexts!",
                                                afe);
                        } finally {
                            ciphertextsReader.close();
                        }

                        session = getSession("mysid" + l, nizkp);

                        if (l < 2) {
                            session.shuffle(ui.getLog(), width, ciphertexts);
                        } else {
                            session.precomp(ui.getLog(), width, 15);
                            session.committedShuffle(ui.getLog(),
                                                     width,
                                                     ciphertexts);
                        }
                    }
                }

                shutdown(ui.getLog());

            } catch (final Throwable e) {
                throw new DemoError("Unable to run demonstration!", e);
            }
        }
    }
}
