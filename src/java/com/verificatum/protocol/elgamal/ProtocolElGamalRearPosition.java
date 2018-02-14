
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
