
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

package com.verificatum.protocol.mixnet;

/**
 * Session parameters.
 *
 * @author Douglas Wikstrom
 */
public final class SessionParams {

    /**
     * Type of proof.
     */
    final String type;

    /**
     * Auxiliary session identifier.
     */
    final String auxsid;

    /**
     * Width of ciphertexts.
     */
    final int width;

    /**
     * Indicates that decryption is verified.
     */
    final boolean dec;

    /**
     * Indicates pre-computation for a shuffle is verified.
     */
    final boolean posc;

    /**
     * Indicates that a shuffle is verified.
     */
    final boolean ccpos;

    /**
     * Session parameters.
     *
     * @param type Type of proof.
     * @param auxsid Auxiliary session identifier.
     * @param width Width of ciphertexts.
     * @param dec Indicates that decryption is verified.
     * @param posc Indicates pre-computation for a shuffle is
     * verified.
     * @param ccpos Indicates that a shuffle is verified.
     */
    SessionParams(final String type,
                  final String auxsid,
                  final int width,
                  final boolean dec,
                  final boolean posc,
                  final boolean ccpos) {
        this.type = type;
        this.auxsid = auxsid;
        this.width = width;
        this.dec = dec;
        this.posc = posc;
        this.ccpos = ccpos;
    }
}
