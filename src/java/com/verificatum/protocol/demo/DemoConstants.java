
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

package com.verificatum.protocol.demo;

/**
 * Constants commonly used in demonstrators.
 *
 * @author Douglas Wikstrom
 */
public final class DemoConstants {

    /**
     * Constructor needed to avoid that this class is instantiated.
     */
    private DemoConstants() {
    }

    /**
     * Number of parties executing the protocol.
     */
    public static final int NO_PARTIES = 3;

    /**
     * Default http directory relative the demo directory.
     */
    public static final String REL_HTTPDIR = "http";
}
