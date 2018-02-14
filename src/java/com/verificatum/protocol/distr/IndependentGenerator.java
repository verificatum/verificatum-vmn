
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

import com.verificatum.arithm.BiExp;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PRingElement;
import com.verificatum.crypto.CryptoPKey;
import com.verificatum.crypto.CryptoSKey;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.protocol.ProtocolBBT;
import com.verificatum.protocol.secretsharing.PedersenSequential;
import com.verificatum.ui.Log;


/**
 * Generates an independent generator of a prime order group. This is
 * essentially a wrapper class for
 * {@link com.verificatum.protocol.secretsharing.PedersenSequential}
 * executed as a Feldman protocol with a randomly chosen secret.
 *
 * <p>
 *
 * This is not a coin-flipping protocol, since the generated group
 * element is not necessarily (pseudo) random. However, if the
 * adversary can compute the logarithm of the generated element
 * without corrupting a threshold of the parties and without breaking
 * the security of the cryptosystem used for the underlying VSS
 * protocol, then an algorithm for computing the logarithm of a
 * randomly chosen element can be constructed. This property suffices
 * for most, if not all, applications.
 *
 * @author Douglas Wikstrom
 */
public final class IndependentGenerator extends ProtocolBBT {

    /**
     * Group for which the independent generator is generated.
     */
    PGroup pGroup;

    /**
     * Our secret key.
     */
    CryptoSKey skey;

    /**
     * All public keys.
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
     * @param pGroup Group in which the generator is generated.
     * @param pkeys Plain public keys of all parties.
     * @param skey Plain secret key.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public IndependentGenerator(final String sid,
                                final ProtocolBBT protocol,
                                final PGroup pGroup,
                                final CryptoPKey[] pkeys,
                                final CryptoSKey skey,
                                final int rbitlen) {
        super(sid, protocol);
        this.pGroup = pGroup;
        this.pkeys = Arrays.copyOf(pkeys, pkeys.length);
        this.skey = skey;
        this.rbitlen = rbitlen;
    }

    /**
     * Generate independent generator.
     *
     * @param log Logging context.
     * @return Generated group element.
     */
    public PGroupElement generate(final Log log) {
        PGroupElement h;

        log.info("Generate independent generator.");

        final Log tempLog = log.newChildLog();
        File file = getFile("IndependentGenerator");
        if (file.exists()) {

            tempLog.info("Read independent generator from file.");

            final ByteTreeReader btr = new ByteTreeReaderF(file);
            h = pGroup.unsafeToElement(btr);
            btr.close();

        } else {

            final BiPRingPGroup biExp = new BiExp(pGroup);
            final HomPRingPGroup hom = biExp.restrict(pGroup.getg());

            final PedersenSequential independentGenerator =
                new PedersenSequential("IndependentGenerator",
                                       this,
                                       hom,
                                       pkeys,
                                       skey,
                                       rbitlen);

            PRingElement secret = null;
            if (j <= threshold) {
                secret = hom.getDomain().randomElement(randomSource, rbitlen);
            }
            independentGenerator.execute(tempLog, secret);

            h = independentGenerator.getConstantElementProduct(tempLog);

            file = getFile("IndependentGenerator");
            h.toByteTree().unsafeWriteTo(file);

            tempLog.info("Write independent generator to file.");

        }
        return h;
    }
}
