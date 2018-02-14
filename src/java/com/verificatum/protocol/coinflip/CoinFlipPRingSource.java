
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPRingElement;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.ui.Log;


/**
 * This is a container class of {@link CoinFlipPRing} that simplifies
 * the handling of jointly generated random "coins". The user may
 * request a random coin by simply calling {@link #getCoin(Log)},
 * provided that all parties agree to do this at the same time of
 * course. The method {@link #prepareCoins(Log,int)} can be used to
 * perform most of the necessary communication and computations in
 * advance for a given number of coins. The prepared coins can then be
 * output quickly with limited communication.
 *
 * <p>
 *
 * This class assumes that all parties agree both on how many coins
 * are precomputed and on the order the coins are used, i.e., the
 * coins are queued and output in the order they are generated. The
 * programmer is responsible for keeping the (honest) parties in
 * synchronization.
 *
 * @author Douglas Wikstrom
 */
public final class CoinFlipPRingSource extends ProtocolBBT {

    /**
     * An "independent" generator.
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
     * A list of the prepared "coins".
     */
    List<CoinFlipPRing> preparedCoins;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Generates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param h An "independent" generator.
     * @param pkeys Plain public keys.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public CoinFlipPRingSource(final String sid,
                               final ProtocolBBT protocol,
                               final PGroupElement h,
                               final CryptoPKey[] pkeys,
                               final CryptoSKey skey,
                               final int rbitlen) {
        super(sid, protocol);
        this.h = h;
        this.skey = skey;
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.rbitlen = rbitlen;

        preparedCoins = new LinkedList<CoinFlipPRing>();
    }

    /**
     * Reads prepared coins from file. It is the responsibility of the
     * programmer to only call this method once.
     *
     * @param log Logging context.
     */
    public void readPrepared(final Log log) {

        log.info("Read prepared coins.");
        final Log tempLog = log.newChildLog();

        final int counter = readInt("Counter");

        for (int i = 0; i < counter; i++) {

            final CoinFlipPRing cfpf =
                new CoinFlipPRing(Integer.toString(i),
                                  this, i, h, pkeys, skey, rbitlen);
            if (!cfpf.used()) {
                cfpf.prepareCoin(tempLog);
                preparedCoins.add(cfpf);
            }
        }
    }

    /**
     * Prepares the given number of additional coins for later use.
     * Although it is not necessary to call this method at all before
     * calling {@link #getCoin(Log)} it allows a protocol to
     * pre-process the generation of random coins.
     *
     * @param log Logging context.
     * @param noCoins Number of coins to prepare.
     */
    public void prepareCoins(final Log log, final int noCoins) {

        log.info("Generate " + noCoins + " coins.");
        final Log tempLog = log.newChildLog();

        final int counter = readInt("Counter");

        final PPGroup pPGroup = new PPGroup(h.getPGroup(), noCoins);

        final String tsid = String.format("Parent%03d", counter);
        final CoinFlipPRing cfpf =
            new CoinFlipPRing(tsid, this, counter, pPGroup.product(h),
                              pkeys, skey, rbitlen);
        cfpf.prepareCoin(tempLog);

        final CoinFlipPRing[] cfpfs = cfpf.getFactors(tempLog);
        for (int i = 0; i < cfpfs.length; i++) {
            preparedCoins.add(cfpfs[i]);
        }
        writeInt("Counter", counter + noCoins);
    }

    /**
     * Returns a random coin. It is a good idea to prepare coins in
     * advance using {@link #prepareCoins(Log,int)} to improve the
     * online complexity of protocols.
     *
     * @param log Logging context.
     * @return Jointly generated random coin.
     */
    public PRingElement getCoin(final Log log) {

        // If no coins are ready we prepare one
        if (preparedCoins.isEmpty()) {
            prepareCoins(log, 1);
        }

        final CoinFlipPRing cfpf = preparedCoins.remove(0);

        log.info("Collect coin.");
        final Log tempLog = log.newChildLog();

        return cfpf.getCoin(tempLog);
    }

    /**
     * Generates a random coin with a given number of bits. It is a
     * good idea to prepare coins in advance using
     * {@link #prepareCoins(Log,int)}.
     *
     * @param log Logging context.
     * @param bitsRequested Number of bits in coin.
     * @param rbitlen Decides statistical distance from the uniform
     * distribution.
     * @return Jointly generated random coin.
     */
    public LargeInteger getCoin(final Log log,
                                final int bitsRequested,
                                final int rbitlen) {
        return LargeInteger.toPositive(getCoinBytes(log,
                                                    bitsRequested,
                                                    rbitlen));
    }

    /**
     * Generates a random coin with a given number of bits. It is a
     * good idea to prepare coins in advance using
     * {@link #prepareCoins(Log,int)} to improve the online complexity
     * of protocols, since generating random coins is expensive. If
     * the number of requested bits <i>n</i> is not a multiple of 8,
     * then the <i>8-(n mod 8)</i> most significant bits of the first
     * output byte are set to zero.
     *
     * @param log Logging context.
     * @param bitsRequested Number of bits in coin.
     * @param rbitlen Decides statistical distance from the uniform
     * distribution.
     * @return Jointly generated random coin.
     */
    public byte[] getCoinBytes(final Log log,
                               final int bitsRequested,
                               final int rbitlen) {

        log.info("Generate " + bitsRequested + " random bits.");
        final Log tempLog = log.newChildLog();

        final int bytesRequested = (bitsRequested + 7) / 8;

        final byte[] result = new byte[bytesRequested];

        // Ensure statistical distance.
        final int offset = (rbitlen + 7) / 8;
        int index = 0;

        // Here we may end up throwing away quite a few random bits,
        // but this is unavoidable, since we can not delay the
        // recovery of part of a ring element (from which the random
        // bits are derived).
        while (index < bytesRequested) {
            final byte[] coins = unpack(getCoin(tempLog), offset);

            final int len =
                Math.min(result.length - index, coins.length - offset);

            System.arraycopy(coins, offset, result, index, len);
            index += len;
        }
        final int z = 8 - bitsRequested % 8;
        if (z > 0) {
            result[0] &= 0xFF >>> z;
        }
        return result;
    }

    /**
     * Returns bytes extracted from the input element.
     *
     * @param el Element to be turned into bytes.
     * @param offset Number of leading bytes to eliminate.
     * @return Extracted bytes.
     */
    protected static byte[] unpack(final PRingElement el, final int offset) {
        if (el instanceof PFieldElement) {

            final byte[] bytes = ((PFieldElement) el).toByteArray();
            return Arrays.copyOfRange(bytes, offset, bytes.length);

        } else {

            final PRingElement[] els = ((PPRingElement) el).getFactors();
            final ArrayList<byte[]> list = new ArrayList<byte[]>();
            for (int i = 0; i < els.length; i++) {
                list.add(unpack(els[i], offset));
            }
            int total = 0;
            for (final byte[] bytes : list) {
                total += bytes.length;
            }
            final byte[] result = new byte[total];
            int index = 0;
            for (final byte[] bytes : list) {
                System.arraycopy(bytes, 0, result, index, bytes.length);
                index += bytes.length;
            }
            return result;

        }
    }
}
