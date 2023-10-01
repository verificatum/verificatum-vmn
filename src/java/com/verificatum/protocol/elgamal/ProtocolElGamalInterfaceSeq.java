
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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import com.verificatum.arithm.LargeIntegerArray;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PGroupElementIterator;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.util.ArrayWorker;


/**
 * Implements a plain El Gamal submission scheme, i.e.,
 * newline-separated hexadecimal coded ciphertexts are simply read
 * from a file.
 *
 * @author Douglas Wikstrom
 */
public abstract class ProtocolElGamalInterfaceSeq
    extends ProtocolElGamalInterface
    implements ProtocolElGamalInterfaceDemo {

    /**
     * Number of ciphertexts in each batch, when the total number of
     * ciphertexts is very large.
     */
    public static final int CIPHERTEXT_BUFFER_SIZE = 100 * 1000;

    /**
     * Returns a writer of ciphertexts in a given format.
     *
     * @param file File to write to.
     * @return Writer of ciphertexts.
     */
    protected abstract CiphertextWriter getCiphertextWriter(final File file);

    /**
     * Returns a reader of ciphertexts in a given format.
     *
     * @param file File to read from.
     * @return Reader of ciphertexts.
     */
    protected abstract CiphertextReader
        getCiphertextReader(final PGroup ciphPGroup, final File file)
        throws ProtocolFormatException;

    /**
     * Returns a decoder of plaintexts in a given format.
     *
     * @param file File to write to.
     * @return Writer of ciphertexts.
     */
    protected abstract PlaintextDecoder getPlaintextDecoder(final File file);

    @Override
    public void writeCiphertexts(final PGroupElementArray ciphertexts,
                                 final File file) {

        CiphertextWriter cw = null;
        PGroupElementIterator pgei = null;

        try {

            cw = getCiphertextWriter(file);
            pgei = ciphertexts.getIterator();

            PGroupElement ciphertext = pgei.next();
            while (ciphertext != null) {
                cw.write(ciphertext);
                ciphertext = pgei.next();
            }

        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to write ciphertexts!", ioe);
        } finally {
            if (cw != null) {
                cw.close();
            }
            if (pgei != null) {
                pgei.close();
            }
        }
    }

    @Override
    public PGroupElementArray readCiphertexts(final PGroup ciphPGroup,
                                              final File file)
        throws ProtocolFormatException {

        final ArrayList<PGroupElementArray> ciphertextArrays =
            new ArrayList<PGroupElementArray>();

        CiphertextReader cr = null;

        try {

            cr = getCiphertextReader(ciphPGroup, file);

            boolean moreElements = true;

            while (moreElements) {

                final ArrayList<PGroupElement> ciphertextList =
                    new ArrayList<PGroupElement>();

                while (ciphertextList.size() < CIPHERTEXT_BUFFER_SIZE) {

                    final PGroupElement element = cr.read();

                    if (element == null) {
                        moreElements = false;
                        break;
                    } else {
                        ciphertextList.add(element);
                    }
                }

                if (!ciphertextList.isEmpty()) {

                    // Convert List<PGroupElement>
                    // to PGroupElement[]
                    // to PGroupElementArray.
                    final int size = ciphertextList.size();
                    final PGroupElement[] ciphertexts =
                        ciphertextList.toArray(new PGroupElement[size]);
                    final PGroupElementArray ciphertextArray =
                        ciphPGroup.toElementArray(ciphertexts);
                    ciphertextArrays.add(ciphertextArray);
                }
            }

            // Convert List<PGroupElementArray>
            // to PGroupElementArray[]
            // and concatenate to PGroupElementArray.
            final int size = ciphertextArrays.size();
            final PGroupElementArray[] resArrays =
                ciphertextArrays.toArray(new PGroupElementArray[size]);
            final PGroupElementArray res = ciphPGroup.toElementArray(resArrays);

            // Free temporary resources.
            for (int i = 0; i < resArrays.length; i++) {
                resArrays[i].free();
            }
            return res;

        } finally {
            cr.close();
        }
    }

    @Override
    public void decodePlaintexts(final PGroupElementArray plaintexts,
                                 final File file) {

        PlaintextDecoder pd = null;
        PGroupElementIterator pgei = null;
        try {

            pd = getPlaintextDecoder(file);
            pgei = plaintexts.getIterator();

            PGroupElement plaintext = pgei.next();
            while (plaintext != null) {
                pd.decode(plaintext);
                plaintext = pgei.next();
            }

        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to decode plaintexts!", ioe);
        } finally {
            if (pd != null) {
                pd.close();
            }
            if (pgei != null) {
                pgei.close();
            }
        }
    }

    /**
     * String of zeros of a given length.
     *
     * @param len Number of zeros.
     * @return String with the given number of zeros.
     */
    public static String zeroString(final int len) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append('0');
        }
        return sb.toString();
    }

    /**
     * Generates an encoding of the alphabet as group elements.
     *
     * @param publicKeyPGroup Group to which the generated plaintexts
     * belong.
     * @return Array of encoded letters.
     */
    private PGroupElement[]
        generateEncodedAlphabet(final PGroup publicKeyPGroup) {

        final PGroupElement[] encodedAlphabet = new PGroupElement[26];

        final byte[] lett = new byte[1];

        for (int i = 0; i < 26; i++) {
            lett[0] = (byte) (i + 65);
            encodedAlphabet[i] = publicKeyPGroup.encode(lett, 0, lett.length);
        }
        return encodedAlphabet;
    }

    /**
     * Generates a batch of dummy plaintext group elements where each
     * plaintext is an encoding of alphabetic letters.
     *
     * @param publicKeyPGroup Public key defining the set of
     * plaintexts.
     * @param encodedAlphabet Alphabetic letters encoded as group
     * elements.
     * @param startIndex Starting position where to source encoded
     * alphabetical letters from the second input.
     * @param batchSize Length of output array of plaintexts.
     * @return Batch of alphabetical letters encoded as group
     * elements.
     */
    private static PGroupElementArray
        partialAlphabeticalm(final PGroup publicKeyPGroup,
                             final PGroupElement[] encodedAlphabet,
                             final int startIndex,
                             final int batchSize) {

        // Generate array of dummy plaintext group elements.
        final PGroupElement[] ma = new PGroupElement[batchSize];

        for (int i = startIndex; i < startIndex + batchSize; i++) {
            ma[i] = encodedAlphabet[i % encodedAlphabet.length];
        }

        // Convert array into a group element array.
        return publicKeyPGroup.toElementArray(ma);
    }

    /**
     * Generates a batch of dummy plaintext group elements where each
     * plaintext is an encoding of an integer, in increasing order.
     *
     * @param publicKeyPGroup Public key defining the set of
     * plaintexts.
     * @param startIndex First integer to be encoded.
     * @param batchSize Number of integers to encode.
     * @return Batch of dummy plaintext group elements encoding
     * integers in increasing order.
     */
    private static PGroupElementArray
        partialNumericalm(final PGroup publicKeyPGroup,
                          final int startIndex,
                          final int batchSize) {

        // Template string of zeros.
        final String zerosString =
            zeroString(publicKeyPGroup.getEncodeLength());

        // Generate dummy plaintexts.
        final PGroupElement[] ma = new PGroupElement[batchSize];

        final ArrayWorker worker = new ArrayWorker(batchSize) {
            @Override
            public void work(final int start, final int end) {
                for (int i = start; i < end; i++) {

                    // Form string representing integer.
                    String tmp = Integer.toString(startIndex + i);
                    String iString = zerosString.substring(tmp.length()) + tmp;

                    // Convert to array of bytes.
                    byte[] iBytes = ExtIO.getBytes(iString);

                    // Encode bytes into a group element.
                    ma[i] = publicKeyPGroup.encode(iBytes, 0, iBytes.length);
                }
            }
        };
        worker.work();

        // Encode plaintexts as group elements.
        return publicKeyPGroup.toElementArray(ma);
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

        final PGroup publicKeyPGroup = publicKey.getPGroup();

        final String s = Integer.toString(noCiphs);

        // Determine if we can generate integers as dummy messages or
        // if they don't fit.
        boolean alphabetical = false;
        PGroupElement[] encodedAlphabet = null;
        if (s.length() > publicKeyPGroup.getEncodeLength()) {
            alphabetical = true;
            encodedAlphabet = generateEncodedAlphabet(publicKeyPGroup);
        }

        // List of partial results.
        final List<PGroupElementArray> partialDummies =
            new ArrayList<PGroupElementArray>();

        // Fill list with partial group element arrays.
        int remaining = noCiphs;
        while (remaining > 0) {

            final int batchSize =
                Math.min(LargeIntegerArray.getBatchSize(), remaining);

            final int startIndex = noCiphs - remaining;

            if (alphabetical) {
                partialDummies.add(partialAlphabeticalm(publicKeyPGroup,
                                                        encodedAlphabet,
                                                        startIndex,
                                                        batchSize));
            } else {
                partialDummies.add(partialNumericalm(publicKeyPGroup,
                                                     startIndex,
                                                     batchSize));
            }

            remaining = remaining - batchSize;
        }

        // Concatenate partial group element arrays.
        final int size = partialDummies.size();
        final PGroupElementArray[] array =
            partialDummies.toArray(new PGroupElementArray[size]);

        final PGroupElementArray m = publicKeyPGroup.toElementArray(array);

        // Encrypt the result.
        final PRing randomizerPRing = publicKeyPGroup.getPRing();

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
