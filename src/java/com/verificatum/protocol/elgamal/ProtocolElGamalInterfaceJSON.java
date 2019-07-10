
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
