
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
 * Container class storing the lower (inclusive) and upper (exclusive)
 * bound of the indices of a subarray of an array.
 *
 * @author Douglas Wikstrom
 */
class ProtocolElGamalRearInterval {

    /**
     * Starting position.
     */
    final int start;

    /**
     * Ending position.
     */
    final int end;

    /**
     * Container class storing the starting and ending index of a
     * subarray of an array.
     *
     * @param start Starting position.
     * @param end Ending position.
     */
    ProtocolElGamalRearInterval(final int start, final int end) {
        this.start = start;
        this.end = end;
    }

    @Override
    public String toString() {
        return String.format("%d-%d", start, end);
    }
}
