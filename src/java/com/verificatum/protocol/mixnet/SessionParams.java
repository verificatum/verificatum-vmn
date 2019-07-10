
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
