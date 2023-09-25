
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
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.ModPGroup;
import com.verificatum.arithm.ModPGroupElement;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.util.SimpleJSON;
import com.verificatum.util.SimpleJSONException;


/**
 * Implements a plain El Gamal submission scheme, i.e.,
 * newline-separated hexadecimal coded ciphertexts are simply read
 * from a file. The outputs are trivially decoded.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceJSONDecode
    extends ProtocolElGamalInterfaceString {

    /**
     * Tag for first parameter.
     */
    public static final String ALPHA_TAG = "alpha";

    /**
     * Tag for second parameter.
     */
    public static final String BETA_TAG = "beta";

    /**
     * Exception used when a tag is missing.
     *
     * @param tag Tag missing.
     * @return Protocol exception with the the given tag.
     */
    private ProtocolFormatException newMissingException(final String tag) {
        return new ProtocolFormatException("Missing " + tag + "!");
    }

    @Override
    public void writePublicKey(final PGroupElement fullPublicKey,
                               final File file) {

        // We can trust the public key to be a pair, but not that each
        // component is a modular group.

        final PPGroup pPGroup = (PPGroup) fullPublicKey.getPGroup();
        final PGroup pGroupg = pPGroup.project(0);
        final PGroup pGroupy = pPGroup.project(1);
        if (!(pGroupg instanceof ModPGroup)
            || !(pGroupy instanceof ModPGroup)) {

            final String e = "The JSON format can only handle modular groups "
                + "(com.verificatum.arithm.ModPGroup).";
            throw new ProtocolError(e);
        }

        final LargeInteger p = ((ModPGroup) pGroupg).getModulus();
        final LargeInteger q = ((ModPGroup) pGroupy).getElementOrder();

        final LargeInteger g =
            ((ModPGroupElement) ((PPGroupElement) fullPublicKey)
             .project(0)).toLargeInteger();
        final LargeInteger y =
            ((ModPGroupElement) ((PPGroupElement) fullPublicKey)
             .project(1)).toLargeInteger();
        final int encoding = ((ModPGroup)pGroupg).getEncoding();

        final String form =
            "{\"g\":\"%s\",\"p\":\"%s\",\"q\":\"%s\",\"y\":\"%s\","
            + "\"encoding\":\"%d\"}";

        try {
            final String ciphertextString =
                String.format(form,
                              g.toString(10),
                              p.toString(10),
                              q.toString(10),
                              y.toString(10),
                              encoding);
            ExtIO.writeString(file, ciphertextString);

        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to write public key!", ioe);
        }
    }

    /**
     * Reads a named integer from the map.
     *
     * @param map Map containing named integers.
     * @param name Name of integer to read
     * @return Integer read from map.
     * @throws ProtocolFormatException If the stored data does not
     * represent an integer.
     */
    private LargeInteger readLargeInteger(final Map<String, String> map,
                                          final String name)
        throws ProtocolFormatException {

        if (map.containsKey(name)) {
            return new LargeInteger(map.get(name));
        } else {
            throw new ProtocolFormatException("Missing "
                                              + name + " in public key!");
        }
    }

    @Override
    public PGroupElement readPublicKey(final File file,
                                       final RandomSource randomSource,
                                       final int certainty)
        throws ProtocolFormatException {

        String publicKeyString = null;
        try {
            publicKeyString = ExtIO.readString(file);
        } catch (final IOException ioe) {
            throw new ProtocolFormatException("Unable to read public key!",
                                              ioe);
        }

        Map<String, String> map = null;
        try {
            map = SimpleJSON.readMap(publicKeyString);
        } catch (final SimpleJSONException sje) {
            throw new ProtocolFormatException("Could not parse!", sje);
        }

        if (map.size() < 4) {
            throw new ProtocolFormatException("Wrong number of values in map!");
        }

        final LargeInteger p = readLargeInteger(map, "p");
        final LargeInteger q = readLargeInteger(map, "q");
        final LargeInteger g = readLargeInteger(map, "g");
        final LargeInteger y = readLargeInteger(map, "y");

        int encoding;
        if (map.containsKey("encoding")) {
            encoding = readLargeInteger(map, "encoding").intValue();
        } else {
            encoding = ModPGroup.SUBGROUP_ENCODING;
            if (q.mul(LargeInteger.TWO).add(LargeInteger.ONE).equals(p)) {
                encoding = ModPGroup.SAFEPRIME_ENCODING;
            }
        }

        try {
            final ModPGroup modPGroup = new ModPGroup(p, q, g, encoding,
                                                      randomSource, certainty);

            if (!modPGroup.contains(y)) {
                final String s = "y does not represent a group element";
                throw new ProtocolFormatException(s);
            }

            final PPGroup pPGroup = new PPGroup(modPGroup, 2);
            return pPGroup.product(modPGroup.getg(), modPGroup.toElement(y));

        } catch (final ArithmFormatException afe) {
            final String e = "Bad integer values!";
            throw new ProtocolFormatException(e, afe);
        }
    }

    /**
     * Constructs a JSON map containing the representations of the two
     * group elements.
     *
     * @param alpha First group element.
     * @param beta Second group element.
     * @return String representing the pair as a JSON map.
     */
    public String pairToString(final PGroupElement alpha,
                               final PGroupElement beta) {

        final String format = "{\"%s\":\"%s\",\"%s\":\"%s\"}";

        final String alphaString =
            ((ModPGroupElement) alpha).toLargeInteger().toString(10);
        final String betaString =
            ((ModPGroupElement) beta).toLargeInteger().toString(10);
        return String.format(format,
                             ALPHA_TAG,
                             alphaString,
                             BETA_TAG,
                             betaString);
    }

    @Override
    public String ciphertextToString(final PGroupElement ciphertext) {

        // We can trust the public key to be a pair, but not that each
        // component is a modular group.

        final PPGroupElement pCiphertext = (PPGroupElement) ciphertext;

        if (pCiphertext.project(0) instanceof PPGroupElement) {

            final PGroupElement[] alphas =
                ((PPGroupElement) pCiphertext.project(0)).getFactors();
            final PGroupElement[] betas =
                ((PPGroupElement) pCiphertext.project(1)).getFactors();

            final StringBuilder sb = new StringBuilder();
            sb.append('[');
            for (int i = 0; i < alphas.length; i++) {
                sb.append(pairToString(alphas[i], betas[i]));
                sb.append(',');
            }
            sb.deleteCharAt(sb.length() - 1);
            sb.append(']');

            return sb.toString();

        } else {

            return pairToString(pCiphertext.project(0), pCiphertext.project(1));
        }
    }

    @Override
    protected PGroupElement stringToCiphertext(final PGroup ciphPGroup,
                                               final String elementString)
        throws ProtocolFormatException {

        LargeInteger alphali = null;
        LargeInteger betali = null;

        final PPGroup pCiphPGroup = (PPGroup) ciphPGroup;
        final PGroup elPGroup = pCiphPGroup.project(0);

        if (elPGroup instanceof PPGroup) {

            List<Map<String, String>> maps = null;
            try {
                maps = SimpleJSON.readMaps(elementString);
            } catch (final SimpleJSONException sje) {
                throw new ProtocolFormatException("Could not parse!", sje);
            }

            final PGroupElement[] alphas = new PGroupElement[maps.size()];
            final PGroupElement[] betas = new PGroupElement[maps.size()];

            final PPGroup pelPGroup = (PPGroup) elPGroup;
            final ModPGroup modPGroup = (ModPGroup) pelPGroup.project(0);

            for (int i = 0; i < alphas.length; i++) {

                final Map<String, String> map = maps.get(i);

                if (map.containsKey(ALPHA_TAG)) {
                    alphali = new LargeInteger(map.get(ALPHA_TAG), 10);
                } else {
                    throw newMissingException(ALPHA_TAG);
                }
                if (map.containsKey(BETA_TAG)) {
                    betali = new LargeInteger(map.get(BETA_TAG), 10);
                } else {
                    throw newMissingException(BETA_TAG);
                }

                alphas[i] = modPGroup.toElement(alphali);
                betas[i] = modPGroup.toElement(betali);
            }

            final PGroupElement el =
                pCiphPGroup.product(pelPGroup.product(alphas),
                                    pelPGroup.product(betas));

            return el;

        } else {

            Map<String, String> map = null;
            try {
                map = SimpleJSON.readMap(elementString);
            } catch (final SimpleJSONException sje) {
                throw new ProtocolFormatException("Could not parse!", sje);
            }

            if (map.containsKey(ALPHA_TAG)) {
                alphali = new LargeInteger(map.get(ALPHA_TAG), 10);
            } else {
                throw newMissingException(ALPHA_TAG);
            }
            if (map.containsKey(BETA_TAG)) {
                betali = new LargeInteger(map.get(BETA_TAG), 10);
            } else {
                throw newMissingException(BETA_TAG);
            }

            final ModPGroup modPGroup = (ModPGroup) elPGroup;
            return pCiphPGroup.product(modPGroup.toElement(alphali),
                                       modPGroup.toElement(betali));
        }
    }

    @Override
    public String decodePlaintext(final PGroupElement plaintext) {
        try {
            final String s = new String(plaintext.decode(), "UTF-8");
            return s.replaceAll("\n", "").replaceAll("\r", "");
        } catch (final UnsupportedEncodingException uee) {
            throw new ProtocolError("Unable to decode plaintext!", uee);
        }
    }
}
