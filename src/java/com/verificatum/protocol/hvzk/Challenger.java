
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

package com.verificatum.protocol.hvzk;

import com.verificatum.eio.ByteTreeBasic;
import com.verificatum.ui.Log;

/**
 * Interface capturing the challenger of a public-coin protocol.
 *
 * @author Douglas Wikstrom
 */
public interface Challenger {

    /**
     * Returns a challenge.
     *
     * @param log Logging context.
     * @param data Input to the random oracle, if this instance
     * generates its challenges using one. This should
     * contain the instance and the messages up to the
     * challenge step.
     * @param vbitlen Number of bits to generate.
     * @param rbitlen Decides the statistical distance from the
     * uniform distribution.
     * @return Challenge bytes.
     */
    byte[] challenge(Log log,
                     ByteTreeBasic data,
                     int vbitlen,
                     int rbitlen);
}
