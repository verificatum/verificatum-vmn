
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
