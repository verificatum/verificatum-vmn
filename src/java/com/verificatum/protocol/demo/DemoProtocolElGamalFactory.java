
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
