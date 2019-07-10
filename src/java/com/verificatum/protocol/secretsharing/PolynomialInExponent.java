
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

import java.util.Arrays;

import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.HomPRingPGroup;
import com.verificatum.arithm.PFieldElement;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupAssociated;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.arithm.PHomPRingPGroup;
import com.verificatum.arithm.PPGroup;
import com.verificatum.arithm.PPGroupElement;
import com.verificatum.arithm.Polynomial;
import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;


/**
 * Implementation of a "polynomial in the exponent". This immutable
 * class is used in Pedersen's (Feldman's) secret sharing scheme
 * {@link Pedersen}.
 *
 * @author Douglas Wikstrom
 */
public final class PolynomialInExponent implements PGroupAssociated {

    /**
     * Underlying homomorphism.
     */
    private HomPRingPGroup hom;

    /**
     * Coefficients in the exponent.
     */
    private PGroupElement[] coeffInExponent;

    /**
     * Creates an instance.
     *
     * @param hom Underlying homomorphism.
     * @param poly Underlying polynomial.
     */
    public PolynomialInExponent(final HomPRingPGroup hom,
                                final Polynomial poly) {
        this.hom = hom;

        if (!hom.getDomain().equals(poly.getPRing())) {
            throw new ProtocolError("Incompatible rings!");
        }
        coeffInExponent = new PGroupElement[poly.getDegree() + 1];

        for (int i = 0; i < coeffInExponent.length; i++) {
            coeffInExponent[i] = hom.map(poly.getCoefficient(i));
        }
        canonicalize();
    }

    /**
     * Creates a trivial instance. This is syntactic sugar for calling
     * {@link #PolynomialInExponent(HomPRingPGroup, Polynomial)} with
     * the constant polynomial equal to 1.
     *
     * @param hom Underlying homomorphism.
     */
    PolynomialInExponent(final HomPRingPGroup hom) {
        this(hom, new Polynomial(hom.getDomain().getPRing().getONE()));
    }

    /**
     * Initializes an instance with the given group elements. This
     * does not copy the input array.
     *
     * @param hom Underlying homomorphism.
     * @param coeffInExponent Array of coefficients in the exponent.
     */
    protected PolynomialInExponent(final HomPRingPGroup hom,
                                   final PGroupElement[] coeffInExponent) {
        this.hom = hom;
        this.coeffInExponent =
            Arrays.copyOfRange(coeffInExponent, 0, coeffInExponent.length);
        if (coeffInExponent.length == 0) {
            throw new ProtocolError("No coefficients!");
        }
        canonicalize();
    }

    /**
     * Creates an instance from a byte tree representation as output
     * by {@link #toByteTree()}.
     *
     * @param hom Underlying homomorphism.
     * @param maxDegree Maximal degree of polynomial in exponent.
     * @param btr A representation of an instance.
     * @throws ProtocolFormatException If the input does not represent
     * an instance.
     */
    public PolynomialInExponent(final HomPRingPGroup hom,
                                final int maxDegree,
                                final ByteTreeReader btr)
        throws ProtocolFormatException {
        try {

            this.hom = hom;
            final PGroup pGroup = hom.getRange();

            coeffInExponent = pGroup.toElements(maxDegree + 1, btr);

            if (coeffInExponent.length == 0) {
                throw new ProtocolFormatException("Zero length!");
            }
            canonicalize();

        } catch (final ArithmFormatException afe) {
            throw new ProtocolFormatException("Malformed element!", afe);
        }
    }

    /**
     * Returns the polynomials in the exponents corresponding to this
     * one over the factors of the underlying group. This assumes that
     * factoring is possible.
     *
     * @return Polynomials corresponding to this one over the factors
     * of the underlying group.
     */
    public PolynomialInExponent[] getFactors() {

        final HomPRingPGroup[] homs = ((PHomPRingPGroup) hom).getFactors();

        final int width = ((PPGroup) coeffInExponent[0].getPGroup()).getWidth();

        final PGroupElement[][] factored =
            new PGroupElement[coeffInExponent.length][];

        for (int i = 0; i < factored.length; i++) {
            factored[i] = ((PPGroupElement) coeffInExponent[i]).getFactors();
        }

        final PolynomialInExponent[] polys = new PolynomialInExponent[width];
        for (int l = 0; l < width; l++) {
            final PGroupElement[] tmp =
                new PGroupElement[coeffInExponent.length];
            for (int i = 0; i < tmp.length; i++) {
                tmp[i] = factored[i][l];
            }
            polys[l] = new PolynomialInExponent(homs[l], tmp);
        }
        return polys;
    }

    /**
     * Returns a representation of the instance that can given as
     * input to {@link
     * #PolynomialInExponent(HomPRingPGroup,int,ByteTreeReader)}. It
     * is the responsibility of the programmer to separately store the
     * group over which this instance is defined.
     *
     * @return Representation of this instance.
     */
    public ByteTreeBasic toByteTree() {
        return getPGroup().toByteTree(coeffInExponent);
    }

    /**
     * Make sure that the top most coefficient in the exponent is a
     * non-unit element.
     */
    void canonicalize() {
        int index = coeffInExponent.length - 1;
        while (index > 0
               && coeffInExponent[index].equals(getPGroup().getONE())) {
            index--;
        }
        if (index < coeffInExponent.length - 1) {
            coeffInExponent = Arrays.copyOfRange(coeffInExponent, 0, index + 1);
        }
    }

    /**
     * Returns the degree of this polynomial in the exponent.
     *
     * @return Degree of this polynomial in the exponent.
     */
    public int getDegree() {
        return coeffInExponent.length - 1;
    }

    /**
     * Returns a given coefficient in the exponent.
     *
     * @param i Index of the coefficient in the exponent to return.
     * @return Coefficient with index <code>i</code>.
     */
    public PGroupElement getElement(final int i) {
        if (i >= coeffInExponent.length) {
            return getPGroup().getONE();
        } else {
            return coeffInExponent[i];
        }
    }

    /**
     * Evaluates the polynomial in the exponent at the {@link
     * com.verificatum.arithm.PField} element given as input.
     *
     * @param el Point at which the polynomial is evaluated in the
     * exponent.
     * @return Value at the given point.
     */
    public PGroupElement evaluate(final PFieldElement el) {
        PGroupElement value = coeffInExponent[0];
        PFieldElement elPower = el;

        for (int i = 1; i < coeffInExponent.length; i++) {
            value = value.mul(coeffInExponent[i].exp(elPower));
            elPower = elPower.mul(el);
        }
        return value;
    }

    /**
     * Evaluates the polynomial in the exponent at the point
     * corresponding to the integer given as input.
     *
     * @param j Integer representing the point at which the polynomial
     * is evaluated in the exponent.
     * @return Value at the given point.
     */
    public PGroupElement evaluate(final int j) {
        return evaluate(getPGroup().getPRing().getPField().toElement(j));
    }

    /**
     * Takes the coefficient-wise product of this instance with the
     * input.
     *
     * @param pie Polynomial in the exponent with which this instance
     * is multiplied.
     * @return Product of this instance and the input.
     */
    public PolynomialInExponent mul(final PolynomialInExponent pie) {

        PolynomialInExponent p1 = this;
        PolynomialInExponent p2 = pie;

        if (p1.getDegree() < p2.getDegree()) {
            final PolynomialInExponent temp = p1;
            p1 = p2;
            p2 = temp;
        }

        final PGroupElement[] product = new PGroupElement[p1.getDegree() + 1];
        int i = 0;
        for (; i < p2.coeffInExponent.length; i++) {
            product[i] = p1.coeffInExponent[i].mul(p2.coeffInExponent[i]);
        }
        System.arraycopy(p1.coeffInExponent, i,
                         product, i,
                         p1.coeffInExponent.length - i);

        return new PolynomialInExponent(hom, product);
    }

    /**
     * Returns the underlying homomorphism.
     *
     * @return Underlying homomorphism.
     */
    public HomPRingPGroup getHom() {
        return hom;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append('(');
        for (int i = 0; i < coeffInExponent.length; i++) {
            sb.append(coeffInExponent[i].toString());
            if (i < coeffInExponent.length - 1) {
                sb.append(',');
            }
        }
        sb.append(')');
        return sb.toString();
    }

    // Documented in arithm.PGroupAssociated.java.

    @Override
    public PGroup getPGroup() {
        return coeffInExponent[0].getPGroup();
    }
}
