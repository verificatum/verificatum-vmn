
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

package com.verificatum.protocol.secretsharing;

import com.verificatum.arithm.ArithmException;
import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PField;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PRing;
import com.verificatum.arithm.PRingElement;
import com.verificatum.arithm.Polynomial;
import com.verificatum.crypto.RandomSource;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;

/**
 * Implements the basic functionality for executing Shamir's secret
 * sharing protocol over an instance of {@link PRing}.
 *
 * @author Douglas Wikstrom
 */
public final class ShamirBasic extends Polynomial {

    /**
     * Creates an instance from the given coefficients of a
     * polynomial.
     *
     * @param coefficients Coefficients of the polynomial.
     */
    protected ShamirBasic(final PRingElement[] coefficients) {
        super(coefficients);
    }

    /**
     * Creates an instance by using the input as sharing polynomial.
     *
     * @param poly Polynomial defining this instance.
     */
    protected ShamirBasic(final Polynomial poly) {
        super(poly);
    }

    /**
     * Creates a random instance with the given degree and constant
     * coefficient.
     *
     * @param degree Degree of the random polynomial.
     * @param constcoefficient Value of the constant coefficient.
     * @param randomSource Source of random bits.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     */
    public ShamirBasic(final int degree,
                       final PRingElement constcoefficient,
                       final RandomSource randomSource,
                       final int rbitlen) {
        super(degree);

        coefficients[0] = constcoefficient;
        final PRing pRing = constcoefficient.getPRing();

        for (int i = 1; i <= degree; i++) {
            coefficients[i] = pRing.randomElement(randomSource, rbitlen);
        }
        canonicalize();
    }

    /**
     * Creates an instance from a byte tree representation.
     *
     * @param pRing Ring over which the instance is defined.
     * @param maxDegree Maximal degree of polynomial.
     * @param btr Representation of instance.
     * @throws ProtocolFormatException If the input is not a
     * representation of an instance.
     */
    public ShamirBasic(final PRing pRing,
                       final int maxDegree,
                       final ByteTreeReader btr)
        throws ProtocolFormatException {
        try {
            init(pRing, maxDegree, btr);
        } catch (final ArithmFormatException afe) {
            final String s = "Input does not represent an instance!";
            throw new ProtocolFormatException(s, afe);
        }
    }

    /**
     * Returns the instances corresponding to this one over the
     * factors of the underlying ring.
     *
     * @return Instances corresponding to this one over the factors of
     * the underlying ring.
     */
    @Override
    public ShamirBasic[] getFactors() {
        final Polynomial[] polyFactors = super.getFactors();
        final ShamirBasic[] factors = new ShamirBasic[polyFactors.length];
        for (int i = 0; i < factors.length; i++) {
            factors[i] = new ShamirBasic(polyFactors[i]);
        }
        return factors;
    }

    /**
     * Recovers the secret from a list of Shamir secret shares. A
     * standard Lagrange interpolation is performed to compute the
     * output. It is assumed that the values given as input reside on
     * a polynomial with degree equal to the number of elements in the
     * two input arrays minus one, i.e., there are no superfluous data
     * points. If this is not the case, then the output is undefined.
     *
     * @param indices Distinct points at which values of the
     * polynomial are given.
     * @param values Values at these points.
     * @param noShares Number of shares to use, i.e., the degree + 1
     * shares.
     * @return Recovered secret.
     */
    public static PRingElement recover(final int[] indices,
                                       final PRingElement[] values,
                                       final int noShares) {
        final int degree = noShares - 1;

        final PRing pRing = values[0].getPRing();
        final PField pField = pRing.getPField();

        // Transform the integer indices into field elements
        final PFieldElement[] indicesPField = new PFieldElement[noShares];
        for (int j = 0; j < noShares; j++) {
            indicesPField[j] = pField.toElement(indices[j]);
        }

        // Lagrange interpolation.
        PRingElement constCoeff = pRing.getZERO();

        for (int j = 0; j <= degree; j++) {

            PFieldElement product = pField.ONE;

            for (int l = 0; l <= degree; l++) {

                if (l != j) {
                    try {

                        product = product.mul(indicesPField[l]
                                              .div(indicesPField[l]
                                                   .sub(indicesPField[j])));

                    } catch (final ArithmException ae) {

                        // If this method is called with valid data,
                        // this never happens.
                        throw new ProtocolError("Unable to invert!", ae);
                    }
                }
            }
            constCoeff = constCoeff.add(values[j].mul(product));
        }
        return constCoeff;
    }

    /**
     * Returns the sum of this instance and the input.
     *
     * @param sb Instance added to this instance.
     * @return Sum of this instance and the input.
     */
    public ShamirBasic add(final ShamirBasic sb) {
        return new ShamirBasic(super.add(sb));
    }
}
