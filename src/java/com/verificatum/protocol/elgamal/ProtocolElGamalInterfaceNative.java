
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

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
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
 * Implements a plain El Gamal submission scheme, i.e.,
 * newline-separated hexadecimal coded ciphertexts are simply read
 * from a file.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceNative
    extends ProtocolElGamalInterfaceString {

    @Override
    public void writePublicKey(final PGroupElement fullPublicKey,
                               final File file) {

        final PGroup pGroup =
            ((PPGroupElement) fullPublicKey).project(0).getPGroup();
        final ByteTreeBasic gbt = Marshalizer.marshal(pGroup);
        final ByteTreeBasic kbt = fullPublicKey.toByteTree();
        final byte[] keyBytes = new ByteTreeContainer(gbt, kbt).toByteArray();

        try {
            ExtIO.writeString(file, Hex.toHexString(keyBytes));

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
            final ByteTreeReader btr =
                new ByteTree(keyBytes, null).getByteTreeReader();

            final PGroup pGroup =
                Marshalizer.unmarshalAux_PGroup(btr.getNextChild(),
                                                randomSource,
                                                certainty);

            return new PPGroup(pGroup, 2).toElement(btr.getNextChild());

        } catch (final IOException ioe) {
            throw new ProtocolFormatException("Malformed key!", ioe);
        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Malformed key!", eioe);
        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Malformed key!", afe);
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
