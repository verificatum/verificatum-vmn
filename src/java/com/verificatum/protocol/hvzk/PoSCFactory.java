
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

package com.verificatum.protocol.hvzk;

import java.io.File;

import com.verificatum.protocol.elgamal.ProtocolElGamal;


/**
 * Factory for instances implementing {@link PoSC}.
 *
 * @author Douglas Wikstrom
 */
public interface PoSCFactory {

    /**
     * Returns a new instance with the given session identifier and
     * parent protocol.
     *
     * @param sid Session identifier.
     * @param protocol Parent protocol.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * com.verificatum.protocol.Protocol#deleteState()} is called.
     * @return Instance of a proof of a shuffle.
     */
    PoSC newPoSC(String sid, ProtocolElGamal protocol, String rosid,
                 File nizkp);
}
