
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

import java.io.File;

import com.verificatum.arithm.BiExp;
import com.verificatum.arithm.BiPRingPGroup;
import com.verificatum.arithm.PGroupElement;
import com.verificatum.eio.EIOException;
import com.verificatum.eio.ExtIO;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.protocol.distr.DKG;
import com.verificatum.ui.Log;
import com.verificatum.ui.UI;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;


/**
 * Implements distributed El Gamal, i.e., key generation and
 * distributed verifiable decryption.
 *
 * @author Douglas Wikstrom
 */
public class DistrElGamal extends ProtocolElGamal {

    /**
     * Default file name root for input ciphertexts.
     */
    public static final String DEFAULT_CIPHERTEXTS_NAME = "Ciphertexts";

    /**
     * Default file name root for decryption factors.
     */
    public static final String DEFAULT_DECRYPTIONFACTORS_NAME =
        "DecryptionFactors";

    /**
     * Default file name root for recovered secret keys.
     */
    public static final String DEFAULT_SECRETKEY_NAME =
        "SecretKey";

    /**
     * Default file name root for commitments in zero-knowledge proofs
     * of correctness for decryption factors.
     */
    public static final String DEFAULT_DECRFACTCOMMITMENT_NAME =
        "DecrFactCommitment";

    /**
     * Default file name root for replies in zero-knowledge proofs of
     * correctness for decryption factors.
     */
    public static final String DEFAULT_DECRFACTREPLY_NAME =
        "DecrFactReply";

    /**
     * Default file name root for the output plaintext elements.
     */
    public static final String DEFAULT_PLAINTEXTELEMENTS_NAME =
        "PlaintextElements";

    /**
     * Distributed keys.
     */
    protected DKG dkg;

    /**
     * Initializes a distributed El Gamal protocol.
     *
     * @param privateInfo Private info of this party.
     * @param protocolInfo Protocol info of this party.
     * @param ui User interface.
     *
     * @throws ProtocolFormatException If the infos are not valid.
     */
    public DistrElGamal(final PrivateInfo privateInfo,
                        final ProtocolInfo protocolInfo,
                        final UI ui)
        throws ProtocolFormatException {
        super(privateInfo, protocolInfo, ui);
    }

    /**
     * Initializes a distributed El Gamal protocol as a child of a
     * parent protocol.
     *
     * @param sid Session identifier of this instance.
     * @param prot Protocol which invokes this one.
     * @param nizkp Destination directory for random oracle
     * proofs. Note that this directory is deleted when {@link
     * #deleteState()} is called.
     */
    public DistrElGamal(final String sid,
                        final ProtocolElGamal prot,
                        final File nizkp) {
        super(sid, prot, null, nizkp);
        dkg = null;
    }

    /**
     * Returns true if and only if keys have been generated, i.e.,
     * sessions of this instance can be created.
     *
     * @return True if and only if keys have been generated.
     */
    public boolean keysAreGenerated() {
        return dkg != null;
    }

    /**
     * Generates a joint public key for which the secret key is secret
     * shared.
     *
     * @param log Logging context.
     */
    public void generatePublicKey(final Log log) {

        dkg = new DKG("", this, pkeys, skey, rbitlen);

        // Generate ElGamal public key. We use the simple
        // exponentiation map, which implies that Feldman verifiable
        // secret sharing is instantiated.
        final BiPRingPGroup biKey = new BiExp(keyPGroup);
        dkg.generate(log, biKey, biKey.getPGroupDomain().getg());
    }

    /**
     * Generates a joint public key for which the secret key is secret
     * shared.
     */
    public void generatePublicKey() {
        generatePublicKey(ui.getLog());
    }

    /**
     * Returns the product of the basic public key and the joint
     * public key, i.e., the full public key.
     *
     * @return Full joint public key.
     */
    public PGroupElement getFullPublicKey() {
        return dkg.getFullPublicKey();
    }

    /**
     * Returns the product of the basic public key and the joint
     * public key, i.e., the full public key.
     *
     * @param width Width of the public key.
     * @return Full joint public key.
     */
    public PGroupElement getWideFullPublicKey(final int width) {
        return dkg.getWideFullPublicKey(width);
    }

    /**
     * Computes the joint public key by taking the product of the
     * y-parts of the public keys of all servers.
     *
     * @return Joint public key.
     */
    public PGroupElement getJointPublicKey() {
        return dkg.getJointPublicKey();
    }

    /**
     * Returns a protocol session that shares some basic variables and
     * the keys of its parent, but not scope on the bulletin board or
     * working directory. This is used to implement sessions.
     *
     * @param auxsid Session identifier for random oracle proofs.
     * @param nizkp Destination directory for random oracle
     * proofs.
     *
     * @return Returns a new session.
     */
    public DistrElGamalSession getSession(final String auxsid,
                                          final File nizkp) {
        if ("".equals(auxsid)) {
            throw new ProtocolError("Attempting to use empty random oracle "
                                    + "session identifier!");
        }
        return new DistrElGamalSession(auxsid, this, auxsid, nizkp);
    }

    /**
     * Writes the full public key to the given directory and all other
     * keys to the given subdirectory.
     *
     * @param nizkp Destination of public key.
     * @param subnizkp Destination of other keys.
     */
    public void writeKeys(final File nizkp, final File subnizkp) {

        final PGroupElement pk = dkg.getFullPublicKey();
        pk.toByteTree().unsafeWriteTo(FPKfile(nizkp));

        try {
            ExtIO.mkdirs(subnizkp);
        } catch (final EIOException eioe) {
            throw new ProtocolError("Unable to create directory for "
                                    + "other keys!", eioe);
        }

        dkg.getPolynomialInExponent().toByteTree().
            unsafeWriteTo(PIEfile(subnizkp));
    }

    /**
     * Name of file containing the polynomial in exponent from which
     * the public keys of all mix-servers can be computed.
     *
     * @param nizkp Destination directory of public key.
     * @return File where the polynomial in exponent is stored.
     */
    public static File PIEfile(final File nizkp) { // NOPMD
        return new File(nizkp, "PolynomialInExponent.bt");
    }

    /**
     * Name of file containing the full public key of this instance.
     *
     * @param nizkp Destination directory of public key.
     * @return File where the public key is stored.
     */
    public static File FPKfile(final File nizkp) { // NOPMD
        return new File(nizkp, "FullPublicKey.bt");
    }
}
