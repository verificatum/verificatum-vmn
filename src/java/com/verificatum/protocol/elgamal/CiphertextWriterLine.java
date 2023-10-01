
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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;

/**
 * Writer of newline separated ciphertexts.
 *
 * @author Douglas Wikstrom
 */
public abstract class CiphertextWriterLine implements CiphertextWriter {

    /**
     * Destination of written ciphertexts.
     */
    protected final BufferedWriter bw;

    /**
     * Creates a writer.
     *
     * @param file Destination of written ciphertexts.
     */
    public CiphertextWriterLine(final File file) throws ProtocolError {
        try {

            final FileOutputStream fos = new FileOutputStream(file);
            final OutputStreamWriter osr =
                new OutputStreamWriter(fos, ExtIO.CHARACTER_ENCODING);
            bw = new BufferedWriter(osr);

        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to write ciphertexts!", ioe);
        }
    }

    /**
     * Returns a string representation of a ciphertext.
     *
     * @param ciphertext Ciphertext to be converted.
     * @return Representation of ciphertext.
     */
    protected abstract String ciphertextToLine(PGroupElement ciphertext);

    @Override
    public void write(PGroupElement ciphertext) throws IOException {
        bw.write(ciphertextToLine(ciphertext));
        bw.newLine();
    }

    @Override
    public void close() {
        ExtIO.strictClose(bw);
    }
}