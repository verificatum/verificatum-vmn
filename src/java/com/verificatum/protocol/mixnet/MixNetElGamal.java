
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

import java.io.File;

import com.verificatum.arithm.PGroupElement;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.elgamal.DistrElGamal;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;

/**
 * Implements a mix-net based on the El Gamal cryptosystem.
 *
 * @author Douglas Wikstrom
 */
public class MixNetElGamal extends ProtocolElGamal {

    /**
     * Name of default width tag.
     */
    public static final String WIDTH = "width";

    /**
     * Name of maximal number of ciphertexts tag tag.
     */
    public static final String MAXCIPH = "maxciph";

    /**
     * Number of bits in exponent used to squeeze lists into a single
     * list before verifying a commitment-consistent proof of a
     * shuffle.
     */
    public static final int RAISED_BITLENGTH = 50;

    /**
     * Distributed El Gamal used to generate keys and decrypt.
     */
    protected DistrElGamal distrElGamal;

    /**
     * Shuffler used to re-randomize and permute ciphertexts.
     */
    protected ShufflerElGamal shufflerElGamal;

    /**
     * Default width of ciphertexts processed by this mix-net.
     */
    protected int width;

    /**
     * Default maximal number of ciphertexts.
     */
    protected int maxciph;

    /**
     * Creates a mix-net.
     *
     * @param privateInfo Private info of this party.
     * @param protocolInfo Protocol info of this party.
     * @param ui User interface.
     *
     * @throws ProtocolFormatException If the mix-net can not be
     * instantiated from the input infos.
     */
    public MixNetElGamal(final PrivateInfo privateInfo,
                         final ProtocolInfo protocolInfo,
                         final UI ui)
        throws ProtocolFormatException {
        super(privateInfo, protocolInfo, ui);

        // Default number of ciphertexts processed in parallel, i.e.,
        // the "width" of the ciphertexts.
        width = protocolInfo.getIntValue(WIDTH);

        // Default maximal number of ciphertexts for which
        // pre-computation is performed.
        maxciph = protocolInfo.getIntValue(MAXCIPH);
    }

    @Override
    public void hookLogEntry() {
        final String s =
            "-----------------------------------------------------------\n"
            + ui.getDescrString(j) + "\n"
            + "-----------------------------------------------------------";
        ui.getLog().plainInfo(s);
    }

    /**
     * Creates a mix-net as a child of the given protocol.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param rosid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * #deleteState()} is called.
     * @param width Default width of processed ciphertexts for which
     * pre-computation is performed.
     * @param maxciph Default number of ciphertexts for which
     * precomputation is performed.
     */
    public MixNetElGamal(final String sid,
                         final ProtocolElGamal prot,
                         final String rosid,
                         final File nizkp,
                         final int width,
                         final int maxciph) {
        super(sid, prot, rosid, nizkp);
        this.width = width;
        this.maxciph = maxciph;
    }

    /**
     * Initializes this mix-net.
     *
     * @param log Logging context.
     */
    @Override
    public void setup(final Log log) {
        super.setup(log);

        writeBoolean(".setup");

        // Note that we let the two instances share their export
        // directories. This works, since the same public key is
        // guarantee to be used when we generate it in
        // generatePublicKey(Log) below.

        shufflerElGamal = new ShufflerElGamal("SEG", this, nizkp);
        distrElGamal = new DistrElGamal("DEG", this, nizkp);
    }

    /**
     * Initializes this mix-net.
     */
    public void setup() {
        setup(ui.getLog());
    }

    /**
     * Return the default width of the mix-net.
     *
     * @return Default width of the mix-net.
     */
    public int getDefaultWidth() {
        return width;
    }

    /**
     * Return the default width of the mix-net.
     *
     * @return Default width of the mix-net.
     */
    public int getDefaultMaxCiph() {
        return maxciph;
    }

    /**
     * Generates an El Gamal public key and initializes the mix-net to
     * use this public key.
     *
     * @param log Logging context.
     */
    public void generatePublicKey(final Log log) {

        if (readBoolean(".setPublicKey")) {
            throw new ProtocolError("Attempting to generate public key "
                                    + "after the public key has been set!");
        }
        if (!readBoolean(".setup")) {
            throw new ProtocolError("Attempting to generate key before "
                                    + "calling setup!");
        }
        writeBoolean(".publicKey");

        distrElGamal.generatePublicKey(log);
        shufflerElGamal.setPublicKey(distrElGamal.getFullPublicKey());
    }

    /**
     * Generates an El Gamal public key and initializes the mix-net to
     * use this public key.
     */
    public void generatePublicKey() {
        generatePublicKey(ui.getLog());
    }

    /**
     * Sets the public key. This should only be used if the mix-net is
     * used to shuffle using an externally generated public key. Note
     * that if you call this method, then you can not let the mix-net
     * generate a public key later.
     *
     * @param publicKey Full El Gamal public key.
     */
    public void setPublicKey(final PGroupElement publicKey) {
        if (readBoolean(".publicKey")) {
            throw new ProtocolError("Attempting to set public key after the "
                                    + "public key has been generated!");
        }
        writeBoolean(".setPublicKey");

        // Note that if this happens, then instantiating the
        // ShufflerElGamal and DistrElGamal in this way does not give
        // completely initialized subprotocols. This is still useful
        // to set a key without running the setup of the mix-net.
        if (shufflerElGamal == null) {
            shufflerElGamal = new ShufflerElGamal("SEG", this, nizkp);
        }
        shufflerElGamal.setPublicKey(publicKey);
    }

    /**
     * Returns the full public key of this mix-net.
     *
     * @return Public key.
     */
    public PGroupElement getPublicKey() {

        if (!(readBoolean(".publicKey") || readBoolean(".publicKey"))) {
            throw new ProtocolError("Requesting public key before it has "
                                    + "been set or generated!");
        }

        return shufflerElGamal.getPublicKey();
    }

    /**
     * Writes all the keys of this instance, including any recovered
     * secret keys, to the given directories.
     *
     * @param nizkp Destination of public key.
     * @param subnizkp Destination of other keys.
     */
    public void writeKeys(final File nizkp, final File subnizkp) {

        if (distrElGamal.keysAreGenerated()) {
            distrElGamal.writeKeys(nizkp, subnizkp);
        }

        // Store public key along with proof.
        if (shufflerElGamal.getPublicKey() != null) {

            final File file = DistrElGamal.FPKfile(nizkp);
            shufflerElGamal.getPublicKey().toByteTree().unsafeWriteTo(file);
        }
    }

    /**
     * Return a session that can be used to shuffle and decrypt
     * ciphertexts.
     *
     * @param auxsid Session identifier for random oracle proofs.
     * @return Mix-net session.
     */
    public MixNetElGamalSession getSession(final String auxsid) {

        if (!readBoolean(".publicKey") && !readBoolean(".setPublicKey")) {
            throw new ProtocolError("Asking for session before any key has "
                                    + "been generated!");
        }

        File sessionNizk = null;
        final String sessionRosid = rosid + "." + auxsid;

        if (nizkp != null) {
            sessionNizk = new File(nizkp, auxsid);
        }

        // Note that if this happens, then instantiating the
        // ShufflerElGamal and DistrElGamal in this way does not give
        // completely initialized subprotocols. This is still useful
        // to be able to delete sessions without running the setup of
        // the mix-net.
        if (shufflerElGamal == null) {

            shufflerElGamal = new ShufflerElGamal("SEG", this, nizkp);
            distrElGamal = new DistrElGamal("DEG", this, nizkp);

        }

        return new MixNetElGamalSession(auxsid,
                                        this,
                                        sessionRosid,
                                        sessionNizk);
    }
}
