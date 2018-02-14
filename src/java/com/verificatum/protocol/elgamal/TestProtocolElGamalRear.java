
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
import java.util.List;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.ModPGroup;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.crypto.PRGHeuristic;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ExtIO;
import com.verificatum.test.TestClass;
import com.verificatum.test.TestParameters;


/**
 * Tests {@link ProtocolElGamalRear}.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public final class TestProtocolElGamalRear extends TestClass {

    /**
     * Prime order group used for testing.
     */
    private final PGroup primeOrderPGroup;

    /**
     * Constructor needed to avoid that this class is instantiated.
     *
     * @param tp Test parameters configuration of the servers.
     * @throws ArithmFormatException If construction of the test fails.
     */
    public TestProtocolElGamalRear(final TestParameters tp)
        throws ArithmFormatException {
        super(tp);
        this.primeOrderPGroup = new ModPGroup(512);
    }

    /**
     * Generate demo group elements.
     *
     * @param rs Source of randomness.
     * @param primeOrderPGroup Underlying prime order group.
     * @param width Width of elements.
     * @param length Number of elements to generate.
     * @return Generated elements.
     */
    protected List<PGroupElement>
        generateElements(final RandomSource rs,
                         final PGroup primeOrderPGroup,
                         final int width,
                         final int length) {

        PGroup pGroup = null;
        if (width == 1) {
            pGroup = primeOrderPGroup;
        } else {
            pGroup = new PPGroup(primeOrderPGroup, width);
        }

        final List<PGroupElement> res = new ArrayList<PGroupElement>();
        for (int i = 0; i < length; i++) {
            res.add(pGroup.randomElement(rs, 50));
        }
        return res;
    }

    /**
     * Tests the ability to construct elements from other elements.
     *
     * @throws Exception when failing test.
     */
    public void constructOutputElement()
        throws Exception {

        final RandomSource rs = new PRGHeuristic(ExtIO.getBytes(tp.prgseed));

        final int length = 10;


        // Extract a single element.
        final List<PGroupElement> inputElementsWidthsOne =
            generateElements(rs, primeOrderPGroup, 1, length);

        final List<ProtocolElGamalRearPosition> positionsSingle =
            new ArrayList<ProtocolElGamalRearPosition>();
        positionsSingle.add(new ProtocolElGamalRearPosition(1, 0));

        final PGroupElement outputElementWidthOneSingle =
            ProtocolElGamalRear
            .constructOutputElement(primeOrderPGroup,
                                    inputElementsWidthsOne,
                                    positionsSingle);
        assert inputElementsWidthsOne.get(1)
            .equals(outputElementWidthOneSingle)
            : "Failed to extract single element!";


        // Combine multiple elements.
        final List<PGroupElement> inputElementsWidthsMult =
            generateElements(rs, primeOrderPGroup, 1, length);

        final List<ProtocolElGamalRearPosition> positionsMult =
            new ArrayList<ProtocolElGamalRearPosition>();
        positionsMult.add(new ProtocolElGamalRearPosition(0, 0));
        positionsMult.add(new ProtocolElGamalRearPosition(2, 0));

        final PGroupElement outputElementWidthMult =
            ProtocolElGamalRear
            .constructOutputElement(primeOrderPGroup,
                                    inputElementsWidthsMult,
                                    positionsMult);

        final PPGroup pPGroupMult = new PPGroup(primeOrderPGroup, 2);
        final PGroupElement outputElementWidthMultCorr =
            pPGroupMult.product(inputElementsWidthsMult.get(0),
                                inputElementsWidthsMult.get(2));

        assert outputElementWidthMultCorr.equals(outputElementWidthMult)
            : "Failed to extract multiple elements!";


        // Combine multiple components.
        final int width = 5;

        final List<PGroupElement> inputElementsWidthsWidth =
            generateElements(rs, primeOrderPGroup, width, length);

        final List<ProtocolElGamalRearPosition> positionsWidth =
            new ArrayList<ProtocolElGamalRearPosition>();
        positionsWidth.add(new ProtocolElGamalRearPosition(0, 0));
        positionsWidth.add(new ProtocolElGamalRearPosition(2, 3));

        final PGroupElement outputElementWidthWidth =
            ProtocolElGamalRear
            .constructOutputElement(primeOrderPGroup,
                                    inputElementsWidthsWidth,
                                    positionsWidth);

        final PPGroup pPGroupWidth = new PPGroup(primeOrderPGroup, 2);

        final PGroupElement first =
            ((PPGroupElement) inputElementsWidthsWidth.get(0)).project(0);
        final PGroupElement second =
            ((PPGroupElement) inputElementsWidthsWidth.get(2)).project(3);


        final PGroupElement outputElementWidthWidthCorr =
            pPGroupWidth.product(first, second);

        assert outputElementWidthWidthCorr.equals(outputElementWidthWidth)
            : "Failed to extract components elements!";
    }
}
