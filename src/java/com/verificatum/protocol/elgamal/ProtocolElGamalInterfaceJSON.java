
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

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.ModPGroup;
import com.verificatum.arithm.ModPGroupElement;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.crypto.RandomSource;


/**
 * Implements a plain El Gamal submission scheme, i.e.,
 * newline-separated hexadecimal coded ciphertexts are simply read
 * from a file. The outputs are trivially decoded.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceJSON
    extends ProtocolElGamalInterfaceJSONDecode {

    /**
     * Decodes an element to a string.
     *
     * @param plaintext Plaintext element to decode.
     * @return Decoded element.
     */
    protected String elToString(final PGroupElement plaintext) {
        return "\""
            + ((ModPGroupElement) plaintext).toLargeInteger().toString(10)
            + "\"";
    }

    @Override
    public String decodePlaintext(final PGroupElement plaintext) {

        if (plaintext instanceof PPGroupElement) {

            final PGroupElement[] plaintexts =
                ((PPGroupElement) plaintext).getFactors();

            final StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (int i = 0; i < plaintexts.length; i++) {
                sb.append(elToString(plaintexts[i]));
                sb.append(',');
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append(']');
            return sb.toString();

        } else {

            return elToString(plaintext);
        }
    }

    @Override
    public void demoCiphertexts(final PGroupElement fullPublicKey,
                                final int noCiphs,
                                final File outputFile,
                                final RandomSource randomSource) {

        final PGroupElement basicPublicKey =
            ((PPGroupElement) fullPublicKey).project(0);
        final PGroupElement publicKey =
            ((PPGroupElement) fullPublicKey).project(1);

        final PGroupElement[] ma = new PGroupElement[noCiphs];

        ModPGroup modPGroup = null;
        if (publicKey instanceof PPGroupElement) {

            modPGroup =
                (ModPGroup) ((PPGroup) publicKey.getPGroup()).project(0);

        } else {

            modPGroup = (ModPGroup) publicKey.getPGroup();
        }

        // Generate dummy plaintexts.
        if (modPGroup.getEncoding() == ModPGroup.RO_ENCODING) {

            PGroupElement el = modPGroup.getg();
            for (int i = 0; i < noCiphs; i++) {
                ma[i] = el;
                el = el.mul(el);
            }

        } else {

            LargeInteger li = new LargeInteger(0);
            for (int i = 0; i < noCiphs; i++) {
                while (!modPGroup.contains(li)) {
                    li = li.add(LargeInteger.ONE);
                }
                ma[i] = modPGroup.toElement(li);
                li = li.add(LargeInteger.ONE);
            }
        }

        // Encode plaintexts as group elements.
        final PGroupElementArray modm = modPGroup.toElementArray(ma);

        PGroupElementArray m = null;
        if (publicKey instanceof PPGroupElement) {
            m = ((PPGroup) publicKey.getPGroup()).product(modm);
        } else {
            m = modm;
        }

        // Encrypt the result.
        final PRing randomizerPRing = m.getPGroup().getPRing();

        final PRingElementArray r =
            randomizerPRing.randomElementArray(noCiphs, randomSource, 20);

        final PGroupElementArray u = basicPublicKey.exp(r);
        final PGroupElementArray t = publicKey.exp(r);
        r.free();

        final PGroupElementArray v = t.mul(m);
        t.free();
        m.free();

        final PGroupElementArray ciphs =
            ((PPGroup) fullPublicKey.getPGroup()).product(u, v);

        writeCiphertexts(ciphs, outputFile);

        ciphs.free();
    }
}
