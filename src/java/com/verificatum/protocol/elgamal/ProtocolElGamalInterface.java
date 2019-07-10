
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

import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.crypto.CryptoException;
import com.verificatum.crypto.PRG;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;


/**
 * Interface of an El Gamal mix-net. This defines the format of: the
 * public key that is used by senders, the input ciphertexts, and the
 * output plaintexts.
 *
 * @author Douglas Wikstrom
 */
public abstract class ProtocolElGamalInterface {

    /**
     * Writes a full public key to file.
     *
     * @param fullPublicKey Full public key.
     * @param file Destination of representation of public key.
     */
    public abstract void writePublicKey(PGroupElement fullPublicKey, File file);

    /**
     * Reads a full public key from file.
     *
     * @param file Source of representation of public key.
     * @param randomSource Source of randomness.
     * @param certainty Determines the error probability when
     * verifying the representation of the underlying
     * group.
     * @return Full public key.
     *
     * @throws ProtocolFormatException If the file does not contain a
     * valid public key.
     */
    public abstract PGroupElement readPublicKey(File file,
                                                RandomSource randomSource,
                                                int certainty)
        throws ProtocolFormatException;

    /**
     * Writes ciphertexts to file.
     *
     * @param ciphertexts Ciphertexts to be written.
     * @param file Destination of representation of ciphertexts.
     */
    public abstract void writeCiphertexts(PGroupElementArray ciphertexts,
                                          File file);

    /**
     * Reads ciphertexts from file.
     *
     * @param pGroup Group to which the ciphertexts belong.
     * @param file Source of representation of ciphertexts.
     * @return Ciphertexts.
     *
     * @throws ProtocolFormatException If the file does not contain
     * valid ciphertexts. The first point of failure should give an
     * error and preferably point to the line of failure in the
     * exception message.
     */
    public abstract PGroupElementArray readCiphertexts(PGroup pGroup, File file)
        throws ProtocolFormatException;

    /**
     * Decodes the input plaintexts to file.
     *
     * @param plaintexts Plaintext elements.
     * @param file Destination of decoded messages.
     */
    public abstract void decodePlaintexts(PGroupElementArray plaintexts,
                                          File file);

    /**
     * Returns an initialized random source as defined by parameters.
     *
     * @param rsFile File containing a string that can be input to
     * {@link Marshalizer#unmarshalHex_RandomSource(String)}
     * .
     * @param seedFile If the random source is a {@link PRG}, then it
     * must contain a sufficiently long seed.
     * @param tmpSeedFile Temporary seed file used to implement atomic
     * write of a new seed.
     * @return Source of random bits.
     *
     * @throws ProtocolError If it is not possible to create a random
     * source from the data on the given files.
     */
    public static RandomSource standardRandomSource(final File rsFile,
                                                    final File seedFile,
                                                    final File tmpSeedFile)
        throws ProtocolError {
        try {
            final String rsString = ExtIO.readString(rsFile);
            final RandomSource randomSource =
                Marshalizer.unmarshalHex_RandomSource(rsString);

            // If the random source is a PRG, then there must
            // exist an associated seed file of sufficient length.
            if (randomSource instanceof PRG) {
                try {
                    ((PRG) randomSource).setSeedReplaceStored(seedFile,
                                                              tmpSeedFile);
                } catch (final CryptoException ce) {
                    final String e = "Unable to read/write PRG seed file! "
                        + "(" + seedFile + ")."
                        + " " + ce.getMessage();
                    throw new ProtocolError(e, ce);
                }
            }
            return randomSource;
        } catch (final IOException ioe) {
            throw new ProtocolError("Unable to read random source file!", ioe);
        } catch (final EIOException eioe) {
            final String e =
                "Unable to create random source! " + "Make sure that "
                + rsFile + " is valid!";
            throw new ProtocolError(e, eioe);
        }
    }
}
