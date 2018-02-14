
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

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import com.verificatum.arithm.BiExpProd;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PHomPRingPGroup;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PPRingElement;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.secretsharing.Pedersen;
import com.verificatum.protocol.secretsharing.PedersenSequential;
import com.verificatum.ui.Log;


/**
 * Implements a coin-flipping protocol using Pedersen verifiable
 * secret sharing, i.e., each party verifiably shares a random value
 * over a ring. Then all random secrets are recovered and the random
 * coin is defined as the sum of these secrets. This is essentially a
 * wrapper class for {@link PedersenSequential} using the
 * exponentiated product map {@link BiExpProd}.
 *
 * <p>
 *
 * For efficiency, the (correct) secret sharings are added up in the
 * natural way into a single joint Pedersen sharing before recovery.
 * The result of the method {@link #prepareCoin(Log)} is that each
 * party shares a random value and the resulting shares are added up
 * locally at each party. Later, the user can call
 * {@link #getCoin(Log)} to actually get the random coin that was
 * prepared.
 *
 * @author Douglas Wikstrom
 */
public final class CoinFlipPRing extends ProtocolBBT {

    /**
     * Instance representing the prepared coin after several instances
     * have been collapsed.
     */
    Pedersen pedersen;

    /**
     * Independent generator.
     */
    PGroupElement h;

    /**
     * Public keys used for communication.
     */
    CryptoPKey[] pkeys;

    /**
     * Secret key of this instance.
     */
    CryptoSKey skey;

    /**
     * Different states an instance of this class can be in.
     */
    enum State {

        /**
         * State directly after creation.
         */
        INITIAL,

            /**
             * State after coin is prepared.
             */
            COIN_PREPARED,

            /**
             * After coin has been collected.
             */
            COIN_COLLECTED
            };

    /**
     * Current state of this instance.
     */
    State state;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Number of this coin.
     */
    int coinNumber;

    /**
     * Parent protocol.
     */
    ProtocolBBT parentProtocol;

    /**
     * Generates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param coinNumber Number of this coin.
     * @param h Independent generator.
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public CoinFlipPRing(final String sid,
                         final ProtocolBBT protocol,
                         final int coinNumber,
                         final PGroupElement h,
                         final CryptoPKey[] pkeys,
                         final CryptoSKey skey,
                         final int rbitlen) {
        super(sid, protocol);

        // We need the parent to collapse instances.
        this.parentProtocol = protocol;

        this.coinNumber = coinNumber;
        this.h = h;
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        this.rbitlen = rbitlen;
        state = State.INITIAL;
    }

    /**
     * Generates an instance that allows recovering a coin. This is
     * used to implement factoring of an instance.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param pedersen Underlying Pedersen instance.
     * @param coinNumber Number of this coin.
     */
    protected CoinFlipPRing(final String sid,
                            final ProtocolBBT protocol,
                            final Pedersen pedersen,
                            final int coinNumber) {
        super(sid, protocol);
        this.pedersen = pedersen;
        this.coinNumber = coinNumber;
        state = State.COIN_PREPARED;
    }

    /**
     * Returns the factors of this instance. This assumes that
     * factoring is possible.
     *
     * @param log Logging context.
     * @return Factors of this instance.
     */
    public CoinFlipPRing[] getFactors(final Log log) {
        if (state == State.INITIAL) {
            throw new ProtocolError("Unable to factor instance in "
                                    + "initial state!");
        }
        if (!(h instanceof PPGroupElement)) {
            throw new ProtocolError("Can not factor over prime order group!");
        }

        final Pedersen[] pedersens = pedersen.getFactors(log);

        final CoinFlipPRing[] coinflips = new CoinFlipPRing[pedersens.length];
        for (int i = 0; i < pedersens.length; i++) {

            final String tsid = String.format("%03d", coinNumber + i);
            coinflips[i] = new CoinFlipPRing(tsid,
                                             parentProtocol,
                                             pedersens[i],
                                             coinNumber + i);
        }
        return coinflips;
    }

    /**
     * Prepares a random coin to be revealed later.
     *
     * @param log Logging context.
     */
    public void prepareCoin(final Log log) {

        log.info("Prepare joint coin.");

        if (state != State.INITIAL) {
            throw new ProtocolError("Attempting to re-prepare coin!");
        }

        // Set up homomorphism.
        final PGroupElement g = h.getPGroup().getg();

        HomPRingPGroup hom = null;
        if (h instanceof PPGroupElement) {

            // We need to make sure that we can later factor this
            // instance if it was executed over a product group.
            final PGroupElement[] hs = ((PPGroupElement) h).getFactors();
            final PGroupElement[] gs = ((PPGroupElement) g).getFactors();

            final HomPRingPGroup[] homs = new HomPRingPGroup[hs.length];
            for (int i = 0; i < homs.length; i++) {

                final BiPRingPGroup biExpProd =
                    new BiExpProd(hs[i].getPGroup(), 2);
                final PPGroup domain = (PPGroup) biExpProd.getPGroupDomain();
                final PGroupElement restriction = domain.product(gs[i], hs[i]);
                homs[i] = biExpProd.restrict(restriction);

            }
            hom = new PHomPRingPGroup(homs);

        } else {

            final BiPRingPGroup biExpProd = new BiExpProd(h.getPGroup(), 2);
            final PGroupElement restriction =
                ((PPGroup) biExpProd.getPGroupDomain()).product(g, h);
            hom = biExpProd.restrict(restriction);

        }

        final Log tempLog = log.newChildLog();

        if (readBoolean("State")) {

            pedersen = new Pedersen("Collapsed_" + sid,
                                    this,
                                    0,
                                    hom,
                                    pkeys,
                                    skey,
                                    rbitlen,
                                    true);
            pedersen.receiveShare(tempLog);

        } else {

            final PedersenSequential pedersenSequential =
                new PedersenSequential(sid,
                                       this,
                                       hom,
                                       pkeys,
                                       skey,
                                       rbitlen,
                                       false);
            final PRingElement secret =
                hom.getDomain().randomElement(randomSource, rbitlen);
            pedersenSequential.execute(tempLog, secret);

            pedersen = pedersenSequential.collapse("Collapsed_" + sid,
                                                   this,
                                                   true,
                                                   tempLog);
            writeBoolean("State");
        }

        state = State.COIN_PREPARED;
    }

    /**
     * Returns <code>true</code> or <code>false</code> depending on if
     * the coin of this instance has already been used or not.
     *
     * @return Usage status of the coin of this instance.
     */
    public boolean used() {
        final File file = getFile("Used");
        return file.exists();
    }

    /**
     * Outputs a prepared coin.
     *
     * @param log Logging context.
     * @return Random coin.
     */
    public PRingElement getCoin(final Log log) {

        // We make sure that this coin can never be reused no matter
        // what the calling protocol does.
        if (used()) {
            throw new ProtocolError("Attempting to reuse coin!");
        }

        log.info("Collect previously prepared joint coin (" + sid + ").");

        if (state != State.COIN_PREPARED) {
            throw new ProtocolError("No coin has been prepared!");
        }

        state = State.COIN_COLLECTED;

        final File file = getFile("Used");
        try {
            if (!file.createNewFile()) {
                throw new ProtocolError("Failed to create coin count file!");
            }
        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to create used file!", ioe);
        }

        final Log tempLog = log.newChildLog();
        return ((PPRingElement) pedersen.recover(tempLog)).project(0);
    }
}
