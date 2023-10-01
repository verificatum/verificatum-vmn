
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
import java.io.File;
import java.io.IOException;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolFormatException;

/**
 * Reader of ciphertexts as JSON byte trees.
 *
 * @author Douglas Wikstrom
 */
public class CiphertextReaderJSON implements CiphertextReader {

    /**
     * Determines if there may be more ciphertexts to read.
     */
    protected boolean hasMore = false;

    /**
     * Group to which ciphertexts belong.
     */
    protected final PGroup ciphPGroup;

    /**
     * Underlying source of data.
     */
    protected final BufferedReader br;

    /**
     * Constructs a reader.
     *
     * @param ciphPGroup Group to which ciphertexts belong.
     * @param file Source of ciphertexts.
     * @throws ProtocolFormatException If ciphertexts cannot be read
     * from the given file.
     */
    public CiphertextReaderJSON(final PGroup ciphPGroup, final File file)
    throws ProtocolFormatException {
        this.ciphPGroup = ciphPGroup;
        try {
            hasMore = true;
            br = ExtIO.getBufferedReader(file);
            final int b = ExtIO.readNextNonWhitespace(br);
            ExtIO.expectByte(b, '[');
        } catch (final IOException ioe) {
            throw new ProtocolFormatException("Unable to open file!", ioe);
        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Unable to read bytes!", eioe);
        }
    }

    @Override
    public PGroupElement read() throws ProtocolFormatException {
        if (!hasMore) {
            return null;
        }
        try {

            final ByteTreeBasic byteTree = ByteTreeBasic.readJSONFrom(br);

            int b = ExtIO.readNextNonWhitespace(br);
            if (b == ']') {
                hasMore = false;
                b = ExtIO.readNextNonWhitespace(br);
                ExtIO.expectByte(b, -1);
            } else {
                ExtIO.expectByte(b, ',');
            }

            return ciphPGroup.toElement(byteTree.getByteTreeReader());

        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Malformed ciphertext!", afe);
        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Unable to read ciphertext "
                                              + "from file!", eioe);
        }
    }

    @Override
    public void close() {
        ExtIO.strictClose(br);
    }
}