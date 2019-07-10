
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
import java.util.ArrayList;
import java.util.List;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeContainer;
import com.verificatum.eio.ByteTreeF;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.Marshalizer;
import com.verificatum.protocol.ProtocolFormatException;


/**
 * Raw interface of an El Gamal mix-net.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceRaw extends ProtocolElGamalInterface
    implements ProtocolElGamalInterfaceDemo {

    @Override
    public void writePublicKey(final PGroupElement fullPublicKey,
                               final File file) {
        final PGroup pGroup =
            ((PPGroupElement) fullPublicKey).project(0).getPGroup();
        final ByteTreeBasic gbt = Marshalizer.marshal(pGroup);
        final ByteTreeBasic kbt = fullPublicKey.toByteTree();

        (new ByteTreeContainer(gbt, kbt)).unsafeWriteTo(file);
    }

    @Override
    public PGroupElement readPublicKey(final File file,
                                       final RandomSource randomSource,
                                       final int certainty)
        throws ProtocolFormatException {

        ByteTreeReader btr = null;
        try {

            btr = new ByteTreeReaderF(file);
            final PGroup keyPGroup =
                Marshalizer.unmarshalAux_PGroup(btr.getNextChild(),
                                                randomSource, certainty);

            return new PPGroup(keyPGroup, 2).toElement(btr.getNextChild());

        } catch (final EIOException eioe) {
            throw new ProtocolFormatException("Malformed key!", eioe);
        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Malformed key!", afe);
        } finally {
            if (btr != null) {
                btr.close();
            }
        }
    }

    @Override
    public void writeCiphertexts(final PGroupElementArray ciphertexts,
                                 final File file) {
        writeElementArray(ciphertexts, file);
    }

    @Override
    public PGroupElementArray readCiphertexts(final PGroup pGroup,
                                              final File file)
        throws ProtocolFormatException {
        return readElementArray(pGroup, file);
    }

    @Override
    public void decodePlaintexts(final PGroupElementArray plaintexts,
                                 final File file) {
        writeElementArray(plaintexts, file);
    }

    @Override
    public void demoCiphertexts(final PGroupElement fullPublicKey,
                                final int noCiphs,
                                final File outputFile,
                                final RandomSource randomSource) {

        final PGroupElement basicPublicKey = ((PPGroupElement) fullPublicKey)
            .project(0);
        final PGroupElement publicKey =
            ((PPGroupElement) fullPublicKey).project(1);

        final PRing pRing = publicKey.getPGroup().getPRing();

        final PGroupElementArray m =
            publicKey.getPGroup().randomElementArray(noCiphs, randomSource, 10);

        final PRingElementArray r =
            pRing.randomElementArray(noCiphs, randomSource, 20);

        final PGroupElementArray u = basicPublicKey.exp(r);
        final PGroupElementArray t = publicKey.exp(r);
        r.free();

        final PGroupElementArray v = t.mul(m);
        t.free();
        m.free();

        final PGroupElementArray ciphs = ((PPGroup) fullPublicKey.getPGroup())
            .product(u, v);

        writeCiphertexts(ciphs, outputFile);
        ciphs.free();
    }

    /**
     * Writes the input array of group elements to file.
     *
     * @param array Ciphertexts to be written.
     * @param file Destination file.
     */
    public void writeElementArray(final PGroupElementArray array,
                                  final File file) {
        array.toByteTree().unsafeWriteTo(file);
    }

    /**
     * Reads an array of group elements from file.
     *
     * @param pGroup Group to which the input elements should belong.
     * @param file Source file.
     * @return Element array.
     * @throws ProtocolFormatException If the input file does not
     * contain a valid representation of an array of elements from the
     * input group.
     */
    public PGroupElementArray readElementArray(final PGroup pGroup,
                                               final File file)
        throws ProtocolFormatException {

        try {

            final ByteTreeBasic bt = new ByteTreeF(file);

            PGroupElementArray res = null;
            ByteTreeReader btr = null;
            try {

                btr = bt.getByteTreeReader();
                res = pGroup.toElementArray(0, btr);

            } finally {
                btr.close();
            }
            return res;

        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Malformed group elements!", afe);
        }
    }

    /**
     * Reads public keys from file.
     *
     * @param filenames Filenames of arrays to be read.
     * @param randomSource Source of randomness.
     * @param certainty Determines the error probability when
     * verifying the representation of the underlying group.
     * @return List of all public keys read from file.
     * @throws ProtocolFormatException If public keys can not be read
     * from the input files or if the public keys are defined over the
     * same prime order group.
     */
    public List<PGroupElement> readPublicKeys(final String[] filenames,
                                              final RandomSource randomSource,
                                              final int certainty)
        throws ProtocolFormatException {

        if (filenames.length == 0) {
            throw new ProtocolFormatException("No filenames!");
        }

        final List<PGroupElement> res = new ArrayList<PGroupElement>();

        for (int i = 0; i < filenames.length; i++) {

            try {

                final File file = new File(filenames[i]);
                final PGroupElement pkey =
                    readPublicKey(file, randomSource, certainty);
                res.add(pkey);

            } catch (ProtocolFormatException cfe) {
                final String e =
                    "Failed to read key from file! (" + filenames[i] + ")";
                throw new ProtocolFormatException(e, cfe);
            }
        }

        final PGroup poPGroup = res.get(0).getPGroup().getPrimeOrderPGroup();
        for (int i = 1; i < res.size(); i++) {

            final PGroup pGroup = res.get(i).getPGroup().getPrimeOrderPGroup();

            if (!poPGroup.equals(pGroup)) {
                final String e =
                    "Public keys are based on different prime order groups!";
                throw new ProtocolFormatException(e);
            }
        }

        return res;
    }

    /**
     * Returns the atomic groups over the input public keys.
     *
     * @param pkeyPGroups Public key groups.
     * @return Atomic groups of the input public keys.
     */
    public PGroup[] getAtomicPGroups(final PGroup[] pkeyPGroups) {
        final PGroup[] atomicPGroups = new PGroup[pkeyPGroups.length];

        for (int i = 0; i < pkeyPGroups.length; i++) {
            atomicPGroups[i] = ((PPGroup) pkeyPGroups[i]).project(0);
        }
        return atomicPGroups;
    }

    /**
     * Returns list of plaintext groups over the given atomic group of
     * the given widths.
     *
     * @param atomicPGroup Atomic group over which plaintexts are defined.
     * @param widths Widths of plaintexts.
     * @return Plaintext groups.
     */
    public PGroup[] getPlainPGroups(final PGroup atomicPGroup,
                                    final int[] widths) {

        final PGroup[] res = new PGroup[widths.length];

        for (int i = 0; i < widths.length; i++) {

            res[i] = ProtocolElGamal.getPlainPGroup(atomicPGroup, widths[i]);
        }
        return res;
    }

    /**
     * Returns list of plaintext groups over the given atomic groups
     * of the given width.
     *
     * @param atomicPGroups Atomic groups over which plaintexts are defined.
     * @param width Width of plaintexts.
     * @return Plaintext groups.
     */
    public PGroup[] getPlainPGroups(final PGroup[] atomicPGroups,
                                    final int width) {

        final PGroup[] res = new PGroup[atomicPGroups.length];

        for (int i = 0; i < atomicPGroups.length; i++) {

            res[i] = ProtocolElGamal.getPlainPGroup(atomicPGroups[i], width);
        }
        return res;
    }

    /**
     * Returns list of ciphertext groups over the given atomic group
     * of the given widths.
     *
     * @param atomicPGroup Atomic group over which plaintexts are defined.
     * @param widths Widths of plaintexts.
     * @return Ciphertext groups.
     */
    public PGroup[] getCiphPGroups(final PGroup atomicPGroup,
                                   final int[] widths) {

        final PGroup[] res = new PGroup[widths.length];

        for (int i = 0; i < widths.length; i++) {

            res[i] = ProtocolElGamal.getCiphPGroup(atomicPGroup, widths[i]);
        }
        return res;
    }

    /**
     * Returns list of ciphertext groups over the given atomic groups
     * of the given width.
     *
     * @param atomicPGroups Atomic groups over which plaintexts are defined.
     * @param width Widths of plaintexts.
     * @return Ciphertext groups.
     */
    public PGroup[] getCiphPGroups(final PGroup[] atomicPGroups,
                                   final int width) {

        final PGroup[] res = new PGroup[atomicPGroups.length];

        for (int i = 0; i < atomicPGroups.length; i++) {

            res[i] = ProtocolElGamal.getCiphPGroup(atomicPGroups[i], width);
        }
        return res;
    }

    /**
     * Reads arrays of group elements from files.
     *
     * @param inputPGroups Groups to which group elements on file are
     * expected to belong.
     * @param filenames Filenames of arrays to be read.
     * @return List of all arrays read from file.
     * @throws ProtocolFormatException If one of the files can not be
     * read.
     */
    public List<PGroupElementArray> readArrays(final PGroup[] inputPGroups,
                                               final String[] filenames)
        throws ProtocolFormatException {

        final List<PGroupElementArray> res =
            new ArrayList<PGroupElementArray>();

        for (int i = 0; i < filenames.length; i++) {

            final File file = new File(filenames[i]);
            try {
                res.add(readElementArray(inputPGroups[i], file));
            } catch (ProtocolFormatException pfe) {
                final String e =
                    String.format("Failed to read the array! (%s)",
                                  filenames[i]);
                throw new ProtocolFormatException(e, pfe);
            }
        }

        final PGroupElementArray firstArray = res.get(0);
        final PGroup firstPGroup = firstArray.getPGroup();

        for (int i = 1; i < res.size(); i++) {

            if (res.get(i).size() != firstArray.size()) {
                final String e = "Input arrays have different lengths!";
                throw new ProtocolFormatException(e);
            }
            if (!res.get(i).getPGroup().equals(firstPGroup)) {
                final String e =
                    "Input arrays are defined over different groups!";
                throw new ProtocolFormatException(e);
            }
        }

        return res;
    }

    /**
     * Writes group element arrays to file.
     *
     * @param arrays Group element arrays to be written to file.
     * @param outputFilenames Output filenames.
     * @throws ProtocolFormatException If the number of ciphertext
     * arrays and the number of output filenames differ.
     */
    public void writeElementArrays(final List<PGroupElementArray> arrays,
                                   final String[] outputFilenames)
        throws ProtocolFormatException {

        if (arrays.size() != outputFilenames.length) {
            final String f =
                "The number of arrays and the number of output filenames "
                + "differ! (%d != %d)";
            final String e =
                String.format(f, arrays.size(), outputFilenames.length);
            throw new ProtocolFormatException(e);
        }

        for (int i = 0; i < outputFilenames.length; i++) {

            final File outputFile = new File(outputFilenames[i]);
            writeElementArray(arrays.get(i), outputFile);
        }
    }
}
