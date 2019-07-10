
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

/**
 * Container class identifying a component of a group element (or
 * array of group elements) within a list of group elements (or list
 * of arrays of group elements). This is used by {@link
 * ProtocolElGamalRearTool}. Two indexes are used: one for identifying
 * a group element (or group element array) within a list of group
 * elements (or group element arrays) and a second index to identify a
 * component thereof.
 *
 * @author Douglas Wikstrom
 */
class ProtocolElGamalRearPosition {

    /**
     * Index identifying a source group element (or array of group
     * elements).
     */
    final int source;

    /**
     * Index identifying a component within a source group element (or
     * array of group elements).
     */
    final int index;

    /**
     * Container class identifying a subarray within a list of source
     * arrays.
     *
     * @param source Index identifying a source group element (or
     * array of group elements).
     * @param index Index identifying a component of a group element
     * (or an array of group elements).
     */
    ProtocolElGamalRearPosition(final int source, final int index) {
        this.source = source;
        this.index = index;
    }

    @Override
    public String toString() {
        return String.format("(%d,%d)", source, index);
    }
}
