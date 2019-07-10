
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

package com.verificatum.protocol.secretsharing;

import java.util.Arrays;

import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.ui.Log;


/**
 * Implements a container class of several {@link Pedersen} instances.
 * This is used in symmetric settings, where each party up to the
 * threshold plays the role of the dealer once in sequential order.
 *
 * @author Douglas Wikstrom
 */
public final class PedersenSequential extends ProtocolBBT {

    /**
     * Underlying homomorphisms.
     */
    private HomPRingPGroup[] homs;

    /**
     * Instances of the Pedersen VSS protocol run as subprotocols by
     * this instance.
     */
    private Pedersen[] pedersen;

    /**
     * List of eliminated parties.
     */
    private boolean[] eliminated;

    /**
     * Public keys used for communication.
     */
    private CryptoPKey[] pkeys;

    /**
     * Secret key of this instance.
     */
    private CryptoSKey skey;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    private int rbitlen;

    /**
     * Generates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param hom Underlying homomorphism.
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param storeToFile Must be true if this instance should store
     * itself to file, and false otherwise.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public PedersenSequential(final String sid,
                              final ProtocolBBT protocol,
                              final HomPRingPGroup hom,
                              final CryptoPKey[] pkeys,
                              final CryptoSKey skey,
                              final int rbitlen,
                              final boolean storeToFile) {
        this(sid, protocol, generateHoms(hom, pkeys.length), pkeys, skey,
             rbitlen, storeToFile);
    }

    /**
     * Creates an array of the given size populated with the given
     * homomorphism.
     *
     * @param hom Underlying homomorphism.
     * @param size Number of copies of the homomorphism.
     * @return Populated array.
     */
    private static HomPRingPGroup[] generateHoms(final HomPRingPGroup hom,
                                                 final int size) {
        final HomPRingPGroup[] tmpHoms = new HomPRingPGroup[size];
        Arrays.fill(tmpHoms, hom);
        return tmpHoms;
    }

    /**
     * Generates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param homs Underlying homomorphisms (this must be indexed from
     * one).
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param storeToFile Must be true if this instance should store
     * itself to file, and false otherwise.
     */
    public PedersenSequential(final String sid,
                              final ProtocolBBT protocol,
                              final HomPRingPGroup[] homs,
                              final CryptoPKey[] pkeys,
                              final CryptoSKey skey,
                              final int rbitlen,
                              final boolean storeToFile) {
        super(sid, protocol);
        this.homs = Arrays.copyOf(homs, homs.length);
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        this.rbitlen = rbitlen;

        // Make room for threshold instances of Pedersen VSS indexed
        // from one.
        pedersen = new Pedersen[threshold + 1];

        // Make room for threshold booleans representing which parties
        // either complained or were pointed out as corrupted, i.e.,
        // player elimination.
        eliminated = new boolean[threshold + 1];
        Arrays.fill(eliminated, false);

        // Each party executes Pedersen as dealer once using its own
        // homomorphism.
        for (int l = 1; l <= threshold; l++) {

            // Create an instance of Pedersen VSS with a unique SID.
            pedersen[l] = new Pedersen(Integer.toString(l), this, l, homs[l],
                                       pkeys, skey, rbitlen, storeToFile);
        }
    }

    /**
     * Generates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param hom Underlying homomorphism (this must be indexed from
     * one).
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @param storeToFile Must be true if this instance should store
     * itself to file, and false otherwise.
     * @param pedersen Underlying instances of {@link Pedersen}.
     * @param eliminated List of eliminated parties.
     */
    public PedersenSequential(final String sid,
                              final ProtocolBBT protocol,
                              final HomPRingPGroup hom,
                              final CryptoPKey[] pkeys,
                              final CryptoSKey skey,
                              final int rbitlen,
                              final boolean storeToFile,
                              final Pedersen[] pedersen,
                              final boolean[] eliminated) {
        this(sid, protocol, hom, pkeys, skey, rbitlen, storeToFile);
        this.pedersen = Arrays.copyOfRange(pedersen, 0, pedersen.length);
        this.eliminated = Arrays.copyOfRange(eliminated, 0, pedersen.length);
    }

    /**
     * Generates an instance of the protocol that does not store
     * itself to file.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param hom Underlying homomorphism.
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public PedersenSequential(final String sid,
                              final ProtocolBBT protocol,
                              final HomPRingPGroup hom,
                              final CryptoPKey[] pkeys,
                              final CryptoSKey skey,
                              final int rbitlen) {
        this(sid, protocol, hom, pkeys, skey, rbitlen, false);
    }

    /**
     * Executes <code>threshold</code> copies of <code>Pedersen</code>
     * where each party sequentially plays the role of the dealer.
     *
     * @param log Logging context.
     * @param secret Secret we share.
     */
    public void execute(final Log log, final PRingElement secret) {

        log.info("Execute Pedersen " + threshold
                 + " times with rotating dealer.");
        final Log tempLog = log.newChildLog();

        // Each party up to threshold executes Pedersen as dealer
        // once.
        for (int l = 1; l <= threshold; l++) {

            // We play the role of the dealer.
            if (l == j) {

                pedersen[l].dealSecret(tempLog, secret);
                eliminated[l] = false;

                // We play the role of a verifier.
            } else {

                eliminated[l] = !pedersen[l].receiveShare(tempLog);

            }
        }

        // All eliminated parties are assigned trivial sharings.
        for (int i = 1; i <= threshold; i++) {
            if (eliminated[i]) {
                pedersen[i].setTrivial(tempLog);
            }
        }
    }

    /**
     * Executes <code>threshold</code> copies of <code>Pedersen</code>
     * where each party sequentially plays the role of the dealer with
     * random shared secrets.
     *
     * @param log Logging context.
     */
    public void execute(final Log log) {
        execute(log, homs[j].getDomain().randomElement(randomSource, rbitlen));
    }

    /**
     * Returns true if and only if the party with the input index has
     * been eliminated.
     *
     * @param l Index of the party.
     * @return true if and only if party <code>l</code> is eliminated.
     */
    public boolean isEliminated(final int l) {
        return eliminated[l];
    }

    /**
     * Collapses all the subprotocols of this instance into a single
     * Pedersen VSS instance considered to be shared correctly by a
     * non-existent party 0. This gives a simpler and more efficient
     * recovery protocol, when the recovered secret values are to be
     * added anyway after recovery.
     *
     * @param sid Session identifier of created <code>Pedersen</code>
     * instance.
     * @param virtualParent Protocol which seemingly invoked the ouput
     * instance of <code>Pedersen</code>.
     * @param storeToFile Must be true if this instance should store
     * itself to file, and false otherwise.
     * @param log Logging context.
     *
     * @return Single instance corresponding to the collapse of the
     * individual instances.
     */
    public Pedersen collapse(final String sid,
                             final ProtocolBBT virtualParent,
                             final boolean storeToFile,
                             final Log log) {
        PedersenBasic cpb = pedersen[1].pedersenBasic;

        for (int i = 2; i <= threshold; i++) {
            cpb = cpb.add(pedersen[i].pedersenBasic);
        }

        // The resulting sharing is considered as correctly dealt by a
        // non-existent Party 0.
        cpb.l = 0;
        return new Pedersen(sid,
                            virtualParent,
                            0,
                            pkeys,
                            skey,
                            cpb,
                            rbitlen,
                            storeToFile,
                            log);
    }

    /**
     * Recovers and returns the secret shared by player
     * <code>l</code>.
     *
     * @param log Logging context.
     * @param l Index of party of which the secret is recovered.
     * @return Shared secret of party <code>l</code>.
     */
    public PRingElement recover(final Log log, final int l) {
        return pedersen[l].recover(log);
    }

    /**
     * Returns the checking element corresponding to the constant
     * coefficient of the polynomial in the exponent of the given
     * party. This turns out to be one of the interesting elements in
     * many applications, where the secret is never recovered.
     *
     * @param log Logging context.
     * @param l Index of the party.
     * @return Constant element of party <code>l</code>.
     */
    public PGroupElement getConstantElement(final Log log, final int l) {
        return pedersen[l].getConstCoeffElement(log);
    }

    /**
     * Returns the product of the checking elements of the constant
     * coefficients of the polynomial in the exponent of all parties.
     * This turns out to be the most interesting element in many
     * applications, where the secret is never recovered, e.g.,
     * distributed key generation.
     *
     * @param log Logging context.
     * @return Product of constant checking elements of all parties.
     */
    public PGroupElement getConstantElementProduct(final Log log) {

        // We compute the group element as the product of the constant
        // checking element of all Pedersen VSS instances.
        PGroupElement result = pedersen[1].getConstCoeffElement(log);
        for (int l = 2; l <= threshold; l++) {
            result = result.mul(pedersen[l].getConstCoeffElement(log));
        }
        return result;
    }
}
