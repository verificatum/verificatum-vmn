
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTree;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Hex;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;


/**
 * Native interface that uses the byte tree representation of objects
 * converted to hexadecimal strings, except that lists of ciphertexts
 * or plaintexts are represented as separate lines in the input which
 * is a more convenient format.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceNative
    extends ProtocolElGamalInterfaceString {

    @Override
    public void writePublicKey(final PGroupElement fullPublicKey,
                               final File file) {

        final ByteTreeBasic byteTree = publicKeyToByteTree(fullPublicKey);

        try {
            ExtIO.writeString(file, Hex.toHexString(byteTree.toByteArray()));

        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to write public key!", ioe);
        }
    }

    @Override
    public PGroupElement readPublicKey(final File file,
                                       final RandomSource randomSource,
                                       final int certainty)
        throws ProtocolFormatException {

        try {

            final String publicKeyString = ExtIO.readString(file);
            final byte[] keyBytes = Hex.toByteArray(publicKeyString);
            final ByteTree byteTree = new ByteTree(keyBytes, null);

            return byteTreeToPublicKey(byteTree, randomSource, certainty);

        } catch (final IOException ioe) {
            throw new ProtocolFormatException("Malformed key!", ioe);
        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Malformed key!", eioe);
        }
    }

    @Override
    public String ciphertextToString(final PGroupElement ciphertext) {
        final byte[] bytes = ciphertext.toByteTree().toByteArray();
        return Hex.toHexString(bytes);
    }

    @Override
    protected PGroupElement
        stringToCiphertext(final PGroup ciphPGroup,
                           final String ciphertextString)
        throws ProtocolFormatException {

        try {

            final byte[] bytes = Hex.toByteArray(ciphertextString);
            final ByteTree bt = new ByteTree(bytes, null);
            final ByteTreeReader btr = bt.getByteTreeReader();

            return ciphPGroup.toElement(btr);

        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Unable to parse ciphertext!",
                                              eioe);
        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Unable to parse ciphertext!",
                                              afe);
        }
    }
}
