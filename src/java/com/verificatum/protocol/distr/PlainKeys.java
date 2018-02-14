
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

import com.verificatum.crypto.CryptoKeyGen;
import com.verificatum.crypto.CryptoKeyPair;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoPKeyTrivial;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.ui.Log;


/**
 * The trivial protocol where each party generates a key pair of a
 * cryptosystem and then shares it with the other parties.
 *
 * @author Douglas Wikstrom
 */
public final class PlainKeys extends ProtocolBBT {

    /**
     * Underlying key generator.
     */
    CryptoKeyGen keyGen;

    /**
     * Secret key of this instance.
     */
    CryptoSKey skey;

    /**
     * Public keys of all parties.
     */
    CryptoPKey[] pkeys;

    /**
     * Decides the statistical distance from the uniform distribution.
     */
    int rbitlen;

    /**
     * Creates an instance of the protocol.
     *
     * @param sid Session identifier of this instance.
     * @param protocol Protocol which invokes this one.
     * @param keyGen Key generator.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public PlainKeys(final String sid,
                     final ProtocolBBT protocol,
                     final CryptoKeyGen keyGen,
                     final int rbitlen) {
        super(sid, protocol);
        this.keyGen = keyGen;
        this.rbitlen = rbitlen;
    }

    /**
     * Recover the state of this instance from file.
     *
     * @param file File containing the state of this instance.
     * @param log Logging context.
     */
    private void restoreState(final File file, final Log log) {

        log.info("Read keys from file.");

        ByteTreeReader btr = null;
        try {
            btr = new ByteTreeReaderF(file);

            skey = Marshalizer.unmarshalAux_CryptoSKey(btr.getNextChild(),
                                                       randomSource,
                                                       rbitlen);
            for (int l = 1; l <= k; l++) {
                pkeys[l] =
                    Marshalizer.unmarshalAux_CryptoPKey(btr.getNextChild(),
                                                        randomSource,
                                                        rbitlen);
            }
        } catch (final EIOException eioe) {
            throw new ProtocolError("Unable to open or read state file!",
                                    eioe);
        } finally {
            if (btr != null) {
                btr.close();
            }
        }
    }

    /**
     * Executes the protocol.
     *
     * @param log Logging context.
     */
    public void generate(final Log log) {

        // Make room for public keys
        pkeys = new CryptoPKey[k + 1];

        log.info("Generate and read plain keys.");
        final Log tempLog = log.newChildLog();

        // Read keys from file if they exist.
        final File file = getFile("Keys");

        if (file.exists()) {
            restoreState(file, tempLog);
            return;
        }

        // Generate a new key
        tempLog.info("Generate key-pair.");
        final CryptoKeyPair keyPair = keyGen.gen(randomSource, rbitlen);

        skey = keyPair.getSKey();
        pkeys[j] = keyPair.getPKey();

        // Read the keys of all parties
        tempLog.info("Exchange public keys with all parties.");
        final Log tempLog2 = tempLog.newChildLog();

        for (int l = 1; l <= k; l++) {

            if (l == j) {

                // Write our public key on the bulletin board
                tempLog2.info("Publish public key.");
                bullBoard.publish("PublicKey",
                                  Marshalizer.marshal(pkeys[j]),
                                  tempLog2);

            } else {

                // Read public key of other party.
                tempLog2.info("Read public key of " + ui.getDescrString(l)
                              + ".");
                final ByteTreeReader reader =
                    bullBoard.waitFor(l, "PublicKey", tempLog2);

                try {

                    pkeys[l] = Marshalizer.unmarshalAux_CryptoPKey(reader,
                                                                   randomSource,
                                                                   rbitlen);
                    tempLog2.info("Parsed public key successfully.");

                } catch (final EIOException eioe) {
                    pkeys[l] = null;
                }
                if (pkeys[l] == null) {
                    final String s = "Unable to parse public key. "
                        + "Setting it to trivial key.";
                    tempLog2.info(s);
                }
                reader.close();
            }
        }

        // If a key is badly formatted we set it to the trivial key.
        for (int l = 1; l <= k; l++) {
            if (pkeys[l] == null) {
                pkeys[l] = new CryptoPKeyTrivial();
            }
        }

        // Write all keys to file.
        tempLog.info("Writing keys to file.");

        final ByteTreeBasic[] byteTrees = new ByteTreeBasic[k + 1];
        byteTrees[0] = Marshalizer.marshal(skey);
        for (int l = 1; l <= k; l++) {
            byteTrees[l] = Marshalizer.marshal(pkeys[l]);
        }
        final ByteTreeBasic byteTree = new ByteTreeContainer(byteTrees);
        byteTree.unsafeWriteTo(getFile("Keys"));
    }

    /**
     * Returns the secret key of this instance.
     *
     * @return Secret key of this instance.
     */
    public CryptoSKey getSKey() {
        return skey;
    }

    /**
     * Returns an array containing the generated public keys.
     *
     * @return Array of all public keys.
     */
    public CryptoPKey[] getPKeys() {
        return Arrays.copyOf(pkeys, pkeys.length);
    }
}
