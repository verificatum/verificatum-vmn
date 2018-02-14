
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

import java.io.File;
import java.util.Arrays;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.secretsharing.Pedersen;
import com.verificatum.protocol.secretsharing.PedersenSequential;
import com.verificatum.protocol.secretsharing.PolynomialInExponent;
import com.verificatum.ui.Log;


/**
 * Implements a basic distributed key generation protocol for a public
 * key for which the secret key is verifiably shared among the
 * parties.
 *
 * @author Douglas Wikstrom
 */
public final class DKG extends ProtocolBBT {

    /**
     * Original basic public key which defines the homomorphism.
     */
    PGroupElement basicPublicKey;

    /**
     * Underlying homomorphism.
     */
    HomPRingPGroup hom;

    /**
     * Sharing polynomial.
     */
    PolynomialInExponent polynomialInExponent;

    /**
     * Holds the secret key of this party.
     */
    PRingElement secretKey;

    /**
     * Public keys used in subprotocols.
     */
    CryptoPKey[] pkeys;

    /**
     * Secret key used in subprotocols.
     */
    CryptoSKey skey;

    /**
     * States in which an instance can be.
     */
    enum State {

        /**
         * Initial state of this instance after instantiation.
         */
        INITIAL,

            /**
             * State after generation of keys completed.
             */
            GENERATION_COMPLETED
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
     * Creates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param pkeys Plain public keys of all parties.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public DKG(final String sid,
               final ProtocolBBT protocol,
               final CryptoPKey[] pkeys,
               final CryptoSKey skey,
               final int rbitlen) {
        super(sid, protocol);
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        this.rbitlen = rbitlen;

        // Set our state.
        state = State.INITIAL;
    }

    /**
     * Generate the keys of a given type.
     *
     * @param log Logging context.
     * @param bi Bilinear map capturing the key generation algorithm.
     * @param basicPublicKey Basic public key used as input to the key
     * generation algorithm.
     */
    public void generate(final Log log, final BiPRingPGroup bi,
                         final PGroupElement basicPublicKey) {

        this.basicPublicKey = basicPublicKey;

        hom = bi.restrict(basicPublicKey);

        log.info("Generate distributed keys.");
        final Log tempLog = log.newChildLog();

        final File file = getFile("KeyAndPoly");
        if (file.exists()) {

            tempLog.info("Read secret key and polynomial in exponent "
                         + "from file.");

            ByteTreeReader btr = null;

            try {

                btr = new ByteTreeReaderF(file);

                polynomialInExponent =
                    new PolynomialInExponent(hom,
                                             threshold - 1,
                                             btr.getNextChild());
                secretKey = hom.getDomain().toElement(btr.getNextChild());

                btr.close();

            } catch (final ProtocolFormatException pfe) {
                throw new ProtocolError("Unable to read secret key!", pfe);
            } catch (final EIOException eioe) {
                throw new ProtocolError("Unable to read secret key!", eioe);
            } catch (final ArithmFormatException afe) {
                throw new ProtocolError("Unable to read secret key!", afe);
            } finally {
                if (btr != null) {
                    btr.close();
                }
            }

            state = State.GENERATION_COMPLETED;

            return;
        }

        // Secret share our secret key and receive shares from others.
        final PedersenSequential pedersenSequential =
            new PedersenSequential("", this, hom, pkeys, skey, rbitlen, false);

        Log tempLog2;
        if (j <= threshold) {

            tempLog.info("Generate secret.");
            final PRingElement secret =
                hom.getDomain().randomElement(randomSource, rbitlen);

            tempLog.info("Share secret and verify sharings of others.");
            tempLog2 = tempLog.newChildLog();
            pedersenSequential.execute(tempLog2, secret);

        } else {

            tempLog.info("Verify sharings of others.");
            tempLog2 = tempLog.newChildLog();
            pedersenSequential.execute(tempLog2, null);

        }

        final Pedersen pedersen =
            pedersenSequential.collapse("collapsed", this, false, tempLog);

        secretKey = pedersen.getShare();
        polynomialInExponent = pedersen.getPolynomialInExponent();

        final ByteTreeBasic btb =
            new ByteTreeContainer(polynomialInExponent.toByteTree(),
                                  secretKey.toByteTree());
        btb.unsafeWriteTo(file);

        state = State.GENERATION_COMPLETED;
    }

    /**
     * Returns the secret key of this party.
     *
     * @return Secret key of this party.
     */
    public PRingElement getSecretKey() {
        return secretKey;
    }

    /**
     * Returns the basic public key.
     *
     * @return Basic public key.
     */
    public PGroupElement getBasicPublicKey() {
        return basicPublicKey;
    }

    /**
     * Returns the public key of a given party.
     *
     * @param l Index of the party owning the public key.
     * @return Public key of party <code>l</code>.
     */
    public PGroupElement getPublicKey(final int l) {

        if (state != State.GENERATION_COMPLETED) {
            throw new ProtocolError("Keys have not been generated!");
        }
        return polynomialInExponent.evaluate(l);
    }

    /**
     * Returns the public keys.
     *
     * @return Public keys of all parties.
     */
    public PGroupElement[] getPublicKeys() {
        final PGroupElement[] publicKeys = new PGroupElement[k + 1];
        for (int l = 1; l <= k; l++) {
            publicKeys[l] = getPublicKey(l);
        }
        return publicKeys;
    }

    /**
     * Returns the group in which the protocol is deployed.
     *
     * @return Group over which the protocol is executed.
     */
    public PGroup getPGroup() {
        return hom.getRange();
    }

    /**
     * Computes the joint public key.
     *
     * @return Joint public key.
     */
    public PGroupElement getJointPublicKey() {
        return polynomialInExponent.getElement(0);
    }

    /**
     * Returns the polynomial in exponent that fixes the set of public
     * keys of the mix-servers.
     *
     * @return Polynomial in exponent that fixes the set of public
     * keys of the mix-servers.
     */
    public PolynomialInExponent getPolynomialInExponent() {
        return polynomialInExponent;
    }

    /**
     * Returns the product element of the basic public key and the
     * joint public key, i.e., the full public key. Morover, the
     * output has been widened by replacing the basic public key and
     * the joint public key by their <code>width</code> power in the
     * corresponding product group. This is useful to encrypt messages
     * from the product group.
     *
     * @param width Width of the public key.
     * @return Full joint public key.
     */
    public PGroupElement getWideFullPublicKey(final int width) {

        if (width == 1) {

            return getFullPublicKey();

        } else {

            final PPGroup basicPPGroup =
                new PPGroup(basicPublicKey.getPGroup(), width);

            final PPGroup pPGroup = new PPGroup(basicPPGroup, 2);

            return pPGroup.product(basicPPGroup.product(getBasicPublicKey()),
                                   basicPPGroup.product(getJointPublicKey()));
        }
    }

    /**
     * Returns the product of the basic public key and the joint
     * public key, i.e., the full public key.
     *
     * @return Full joint public key.
     */
    public PGroupElement getFullPublicKey() {
        final PPGroup pPGroup =
            new PPGroup(basicPublicKey.getPGroup(),
                        getJointPublicKey().getPGroup());
        return pPGroup.product(getBasicPublicKey(), getJointPublicKey());
    }
}
