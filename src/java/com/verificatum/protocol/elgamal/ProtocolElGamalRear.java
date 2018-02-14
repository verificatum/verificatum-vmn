
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PGroupUtil;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElementArray;
import com.verificatum.protocol.ProtocolFormatException;


/**
 * Functionality to choose subsets of the group elements of public
 * keys, lists of ciphertxts, and lists of plaintexts.
 *
 * @author Douglas Wikstrom
 */
public final class ProtocolElGamalRear {

    /**
     * Avoid accidental instantiation.
     */
    private ProtocolElGamalRear() { }

    /**
     * Returns a group element from a product group constructed from
     * the components of several group elements from product
     * groups. Each position identifies an input source group element
     * and which component in that group element to be used.
     *
     * @param atomicPGroup Atomic group over which the cryptosystem is
     * defined.
     * @param inputElements Input source group elements.
     * @param positions List of positions identifying components of
     * source group elements.
     * @return Group element constructed from the identified
     * components of source group elements.
     * @throws ProtocolFormatException If the positions are
     * incompatible with the source group elements.
     */
    public static PGroupElement
        constructOutputElement(final PGroup atomicPGroup,
                               final List<PGroupElement> inputElements,
                              final List<ProtocolElGamalRearPosition> positions)
        throws ProtocolFormatException {

        final PGroup[] pGroups = new PGroup[positions.size()];
        final PGroupElement[] pieces = new PGroupElement[positions.size()];

        for (int i = 0; i < pGroups.length; i++) {

            final ProtocolElGamalRearPosition position = positions.get(i);
            try {
                pieces[i] = PGroupUtil.getElement(atomicPGroup,
                                                  inputElements,
                                                  position.source,
                                                  position.index);
            } catch (ArithmFormatException afe) {
                final String e = "Could not get group element!";
                throw new ProtocolFormatException(e, afe);
            }
            pGroups[i] = pieces[i].getPGroup();
        }

        if (pieces.length == 1) {

            return pieces[0];

        } else {

            final PPGroup pPGroup = new PPGroup(pGroups);
            return pPGroup.product(pieces);
        }
    }

    /**
     * Returns a group element array from a product group constructed
     * from the parts of several element arrays from product
     * groups. Each position identifies an input group element array
     * and which part in that group element array to be used.
     *
     * @param atomicPGroup Atomic group.
     * @param inputArrays Input source arrays.
     * @param positions List of indices identifying source subarrays.
     * @return Array constructed from the identified subarrays.
     * @throws ProtocolFormatException If the positions are
     * incompatible with the input group element arrays.
     */
    public static PGroupElementArray
        constructOutputArray(final PGroup atomicPGroup,
                             final List<PGroupElementArray> inputArrays,
                             final List<ProtocolElGamalRearPosition> positions)
        throws ProtocolFormatException {

        final PGroup[] pGroups = new PGroup[positions.size()];
        final PGroupElementArray[] pieces =
            new PGroupElementArray[positions.size()];

        for (int i = 0; i < pGroups.length; i++) {

            final ProtocolElGamalRearPosition position = positions.get(i);
            try {
                pieces[i] = PGroupUtil.getElementArray(atomicPGroup,
                                                       inputArrays,
                                                       position.source,
                                                       position.index);
            } catch (ArithmFormatException afe) {
                final String e = "Could not get group element array!";
                throw new ProtocolFormatException(e, afe);
            }
            pGroups[i] = pieces[i].getPGroup();
        }

        if (pieces.length == 1) {

            return pieces[0];

        } else {

            final PPGroup pPGroup = new PPGroup(pGroups);
            return pPGroup.product(pieces);
        }
    }

    /**
     * Re-arrange the input group elements into new output group
     * elements consisting of components of the original group
     * elements.
     *
     * @param atomicPGroup Atomic group.
     * @param inputElements Source elements.
     * @param format Description of which parts of elements should be
     * combined into new elements.
     * @return Re-arranged group elements.
     * @throws ProtocolFormatException If the given format is
     * incompatible with the source group elements.
     */
    public static List<PGroupElement>
        rearrangeElements(final PGroup atomicPGroup,
                          final List<PGroupElement> inputElements,
                          final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        final List<PGroupElement> res = new ArrayList<PGroupElement>();

        for (final List<ProtocolElGamalRearPosition> positions : format) {
            res.add(constructOutputElement(atomicPGroup,
                                           inputElements,
                                           positions));
        }

        return res;
    }

    /**
     * Re-arrange the input group element arrays into new output group
     * element arrays consisting of components of the original group
     * element arrays.
     *
     * @param atomicPGroup Atomic group.
     * @param inputArrays Source group element arrays.
     * @param format Description of which parts of group element
     * arrays should be combined into new group element arrays.
     * @return Re-arranged group element arrays.
     * @throws ProtocolFormatException If the given format is
     * incompatible with the source group element arrays.
     */
    public static List<PGroupElementArray>
        rearrangeArrays(final PGroup atomicPGroup,
                        final List<PGroupElementArray> inputArrays,
                        final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        final List<PGroupElementArray> res =
            new ArrayList<PGroupElementArray>();

        for (final List<ProtocolElGamalRearPosition> source : format) {
            res.add(constructOutputArray(atomicPGroup, inputArrays, source));
        }

        return res;
    }

    /**
     * Factor the group element arrays of the input list.
     *
     * @param width Width of group elements in the group element
     * arrays.
     * @param inputArrays Group of element arrays to be factored.
     * @return Factors of input arrays.
     */
    public static List<PGroupElementArray>
        factorArrays(final int width,
                     final List<PGroupElementArray> inputArrays) {

        if (width == 1) {

            return inputArrays;

        } else {

            final List<PGroupElementArray> res =
                new ArrayList<PGroupElementArray>();

            for (final PGroupElementArray inputArray : inputArrays) {

                final PGroupElementArray[] factors =
                    ((PPGroupElementArray) inputArray).getFactors();

                res.addAll(Arrays.asList(factors));
            }
            return res;
        }
    }

    /**
     * Take the product of the group element arrays of the input list.
     *
     * @param width Width of group elements in the output group
     * element arrays.
     * @param factorArrays Group of element arrays to be factored.
     * @return Product group element arrays.
     */
    public static List<PGroupElementArray>
        productArrays(final int width,
                      final List<PGroupElementArray> factorArrays) {

        if (width == 1) {

            return factorArrays;

        } else {

            final List<PGroupElementArray> res =
                new ArrayList<PGroupElementArray>();

            final int noOutputArrays = factorArrays.size() / width;

            for (int i = 0; i < noOutputArrays; i++) {

                final PGroupElementArray[] factors =
                    new PGroupElementArray[width];

                for (int j = 0; j < factors.length; j++) {
                    factors[j] = factorArrays.get(i * width + j);
                }

                final PGroup factorPGroup = factorArrays.get(i).getPGroup();
                final PPGroup pPGroup = new PPGroup(factorPGroup, width);

                res.add(pPGroup.product(factors));
            }

            return res;
        }
    }

    /**
     * Expands a list of position into a list of translated list of
     * positions.
     *
     * @param width Width used to expand list of positions.
     * @param positions List of positions.
     * @return List of translated lists of positions.
     */
    public static List<List<ProtocolElGamalRearPosition>>
        expandPositions(final int width,
                        final List<ProtocolElGamalRearPosition> positions) {

        final List<List<ProtocolElGamalRearPosition>> res =
            new ArrayList<List<ProtocolElGamalRearPosition>>();

        for (int i = 0; i < width; i++) {

            final List<ProtocolElGamalRearPosition> newPositions =
                new ArrayList<ProtocolElGamalRearPosition>();

            for (final ProtocolElGamalRearPosition position : positions) {

                final int newSource = width * position.source + i;

                final ProtocolElGamalRearPosition newPosition =
                    new ProtocolElGamalRearPosition(newSource, position.index);
                newPositions.add(newPosition);
            }

            res.add(newPositions);
        }
        return res;
    }

    /**
     * Expands format.
     *
     * @param width Width used to expand list of positions.
     * @param format Description of which parts of group element
     * arrays should be combined into new group element arrays.
     * @return Expanded format.
     */
    public static List<List<ProtocolElGamalRearPosition>>
        expandFormat(final int width,
                     final List<List<ProtocolElGamalRearPosition>> format) {

        final List<List<ProtocolElGamalRearPosition>> res =
            new ArrayList<List<ProtocolElGamalRearPosition>>();

        for (final List<ProtocolElGamalRearPosition> row : format) {
            res.addAll(expandPositions(width, row));
        }
        return res;
    }

    /**
     * Re-arrange the input group element arrays into new output group
     * element arrays consisting of components of the original group
     * element arrays.
     *
     * @param width Width used to expand list of positions.
     * @param primeOrderPGroup Underlying prime order group.
     * @param inputArrays Source group element arrays.
     * @param format Description of which parts of group element
     * arrays should be combined into new group element arrays.
     * @return Re-arranged group element arrays.
     * @throws ProtocolFormatException If the given format is
     * incompatible with the source group element arrays.
     */
    public static List<PGroupElementArray>
        rearrangeArraysDeep(final int width,
                            final PGroup primeOrderPGroup,
                            final List<PGroupElementArray> inputArrays,
                           final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        final List<PGroupElementArray> factorArrays =
            factorArrays(width, inputArrays);

        final List<List<ProtocolElGamalRearPosition>> expandedFormat =
            expandFormat(width, format);

        final List<PGroupElementArray> rearrangedArrays =
            rearrangeArrays(primeOrderPGroup, factorArrays, expandedFormat);

        return productArrays(width, rearrangedArrays);
    }

    /**
     * Re-arrangees the input arrays of ciphertexts.
     *
     * @param atomicPGroup Atomic group.
     * @param format Format for the output.
     * @param inCiphertextArrays Input source arrays.
     * @return Re-arranged array of ciphertexts.
     * @throws ProtocolFormatException If the format is incompatible
     * with the input group element arrays.
     */
    public static List<PGroupElementArray>
        rearrangeCiphs(final PGroup atomicPGroup,
                       final List<PGroupElementArray> inCiphertextArrays,
                       final List<List<ProtocolElGamalRearPosition>> format)
        throws ProtocolFormatException {

        // Splice the lists into the first and second components of
        // the ciphertexts.
        List<PGroupElementArray> uparts = null;
        List<PGroupElementArray> vparts = null;

        try {
            uparts = PGroupUtil.unsafeProjects(inCiphertextArrays, 0);
            vparts = PGroupUtil.unsafeProjects(inCiphertextArrays, 1);
        } catch (ArithmFormatException afe) {
            final String e = "Failed to project to part of ciphertexts!";
            throw new ProtocolFormatException(e, afe);
        }

        // Re-arrange each part separately.
        final List<List<PGroupElementArray>> res =
            new ArrayList<List<PGroupElementArray>>();

        res.add(rearrangeArrays(atomicPGroup, uparts, format));
        res.add(rearrangeArrays(atomicPGroup, vparts, format));

        // Combine the results to ciphertexts.
        try {
            return PGroupUtil.products(res);
        } catch (ArithmFormatException afe) {
            throw new ProtocolFormatException("Failed to take products!", afe);
        }
    }

    /**
     * Extracts subsequences from a group element array.
     *
     * @param inputArray Input group element arrays.
     * @param intervals Intervals indicating subsequences of the input
     * group element array.
     * @return Extracted subsequences.
     * @throws ProtocolFormatException If the inputs are invalid.
     */
    public static List<PGroupElementArray>
        subArrays(final PGroupElementArray inputArray,
                  final List<ProtocolElGamalRearInterval> intervals)
        throws ProtocolFormatException {

        final int size = intervals.size();

        final List<PGroupElementArray> res =
            new ArrayList<PGroupElementArray>();

        for (int i = 0; i < size; i++) {

            final int e = intervals.get(i).end;
            if (e > inputArray.size()) {
                final String f =
                    "Interval out of bounds! %d-%d. Length of array is %d!";

                final int s = intervals.get(i).start;
                final String ee = String.format(f, s, e, inputArray.size());
                throw new ProtocolFormatException(ee);
            }
        }

        for (int i = 0; i < size; i++) {

            final int s = intervals.get(i).start;
            final int e = intervals.get(i).end;

            res.add(inputArray.copyOfRange(s, e));
        }
        return res;
    }

    /**
     * Concatenate the input group element arrays.
     *
     * @param inputArrays Input group element arrays.
     * @return Concatenated arrays.
     */
    public static PGroupElementArray
        catArrays(final PGroupElementArray[] inputArrays) {
        final PGroup inputPGroup = inputArrays[0].getPGroup();
        return inputPGroup.toElementArray(inputArrays);
    }
}
