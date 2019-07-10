
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

package com.verificatum.protocol.demo;

import java.io.File;

import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.elgamal.ProtocolElGamalGen;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.InfoException;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.opt.Opt;


/**
 * Factory for running demos with El Gamal ciphertexts.
 *
 * @author Douglas Wikstrom
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public abstract class DemoProtocolElGamalFactory {

    /**
     * Generator of info objects.
     */
    protected ProtocolElGamalGen gen;

    /**
     * Creates a root protocol.
     */
    public DemoProtocolElGamalFactory() {
        gen = new ProtocolElGamalGen();
    }

    /** Creates a root protocol.
     *
     * @param privateInfoFilename Name of file containing private
     * info.
     * @param protocolInfoFilename Name of file containing protocol
     * info.
     * @param ui User interface.
     * @return Runnable version of this protocol.
     * @throws Exception if creating a new protocol fails.
     */
    public DemoProtocol newProtocol(final String privateInfoFilename,
                                    final String protocolInfoFilename,
                                    final UI ui)
        throws Exception {
        return newProtocol(newPrivateInfo().parse(privateInfoFilename),
                           newProtocolInfo().parse(protocolInfoFilename),
                           ui);
    }

    /**
     * Creates a root protocol.
     *
     * @param pri Private info.
     * @param pi Protocol info.
     * @param ui User interface.
     * @return Runnable version of this protocol.
     * @throws Exception if creating a new protocol fails.
     */
    public abstract DemoProtocol newProtocol(PrivateInfo pri,
                                             ProtocolInfo pi,
                                             UI ui)
        throws Exception;

    /**
     * Creates a new protocol info instance containing only the
     * default fields.
     *
     * @return Instance containing only default fields.
     */
    public ProtocolInfo newProtocolInfo() {
        return gen.newProtocolInfo();
    }

    /**
     * Creates a new private info instance containing only the default
     * fields.
     *
     * @return Instance containing only default fields.
     */
    public PrivateInfo newPrivateInfo() {
        return gen.newPrivateInfo();
    }

    /**
     * Initializes the default fields of the input protocol info.
     *
     * @param pi Protocol info.
     * @param demo Demonstraction instance.
     * @param opt Options given by the user.
     * @throws InfoException if generation of the protocol info fails.
     */
    public void generateProtocolInfo(final ProtocolInfo pi,
                                     final Demo demo,
                                     final Opt opt)
        throws InfoException {
        demo.addDefaultValues(pi, opt);
        demo.addDefaultPartyInfos(pi, opt);
    }

    /**
     * Initializes the default fields of the input private info.
     *
     * @param pi Private info.
     * @param pri Protocol info.
     * @param demo Demonstraction instance.
     * @param opt Options given by the user.
     * @param j Index of party.
     */
    public void generatePrivateInfo(final PrivateInfo pi,
                                    final ProtocolInfo pri,
                                    final Demo demo,
                                    final Opt opt,
                                    final int j) {
        demo.addDefaultValues(pi, j, opt);
    }

    /**
     * Writes a private info file to <code>privateInfoFile</code>.
     *
     * @param demo Demonstrator invoking this factory (allows
     * call-backs).
     * @param partyDir Directory of the party of which the protocol
     * info is generated.
     * @param protocolInfoFile Where the protocol info file is
     * written.
     * @param opt Command line parser from which configuration data
     * may be extracted.
     * @return Protocol info file.
     * @throws InfoException if generation of the protocol info fails.
     */
    public ProtocolInfo generateProtocolInfoFile(final Demo demo,
                                                 final File partyDir,
                                                 final File protocolInfoFile,
                                                 final Opt opt)
        throws InfoException {
        final ProtocolInfo pi = newProtocolInfo();
        generateProtocolInfo(pi, demo, opt);
        try {
            pi.toXML(protocolInfoFile);
        } catch (final InfoException ie) {
            throw new ProtocolError("Could not write protocol info file!", ie);
        }
        return pi;
    }

    /**
     * Writes a private info file to <code>privateInfoFile</code>.
     *
     * @param demo Demonstrator invoking this factory (allows
     * call-backs).
     * @param partyDir Directory of the party of which the private
     * info is generated.
     * @param privateInfoFile Where the private info file is written.
     * @param pi Protocol info.
     * @param j Index of the party of which the private info is
     * generated.
     * @param opt Command line parser from which configuration data
     * may be extracted.
     */
    public void generatePrivateInfoFile(final Demo demo,
                                        final File partyDir,
                                        final File privateInfoFile,
                                        final ProtocolInfo pi,
                                        final int j,
                                        final Opt opt) {
        final PrivateInfo pri = newPrivateInfo();
        generatePrivateInfo(pri, pi, demo, opt, j);
        try {
            pri.toXML(privateInfoFile);
        } catch (final InfoException ie) {
            throw new ProtocolError("Could not write private info file!", ie);
        }
    }

    /**
     * Verifies that all servers ended in a consistent state and
     * throws an appropriate exception otherwise. Exactly what
     * consistent means depends on the protocol. The servers must have
     * completed their execution before they are used as parameters to
     * this function. We index from one, i.e., the first input is
     * always null. This is to be consistent with the indexing used
     * elsewhere.
     *
     * @param servers Servers to be verified.
     * @throws Exception if verification fails.
     */
    public abstract void verify(final DemoProtocol... servers) throws Exception;
}
