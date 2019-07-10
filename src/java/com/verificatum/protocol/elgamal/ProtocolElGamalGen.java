
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

package com.verificatum.protocol.elgamal;

import com.verificatum.crypto.RandomSource;
import com.verificatum.protocol.ProtocolBBTGen;
import com.verificatum.protocol.ProtocolDefaults;
import com.verificatum.protocol.ProtocolError;
import com.verificatum.protocol.com.BullBoardBasicGen;
import com.verificatum.ui.info.IntField;
import com.verificatum.ui.info.InfoException;
import com.verificatum.ui.info.PrivateInfo;
import com.verificatum.ui.info.ProtocolInfo;
import com.verificatum.ui.info.StringField;

/**
 * Defines the additional information fields and default values that
 * stored in the protocol and private info files used by a protocol
 * based on El Gamal {@link ProtocolElGamal}.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalGen extends ProtocolBBTGen {

    /**
     * Maximal value for bit lengths of various challenges.
     */
    public static final int MAX_BITLEN = 2048;

    /**
     * Description of nizkp field.
     */
    public static final String NIZKP_DESCRIPTION =
        "Destination directory for non-interactive proof. Paths are "
        + "relative to the working directory or absolute. WARNING! This field "
        + "is not validated syntactically.";

    /**
     * Creates an instance for a given implementation of a bulletin
     * board.
     *
     * @param bbbg Adds the values needed by the particular
     * instantiation of bulletin board used.
     */
    public ProtocolElGamalGen(final BullBoardBasicGen bbbg) {
        super(bbbg);
    }

    /**
     * Creates an instance for the default bulletin board.
     */
    public ProtocolElGamalGen() {
        super();
    }

    @Override
    public void addProtocolInfo(final ProtocolInfo pi) {
        super.addProtocolInfo(pi);

        String s;

        s = "Group over which the protocol is executed. An instance of "
            + "a subclass of com.verificatum.arithm.PGroup.";
        pi.addInfoField(new StringField(ProtocolElGamal.PGROUP, s, 1, 1));

        s = "Width of El Gamal keys. If equal to one the standard El Gamal "
            + "cryptosystem is used, but if it is greater than one, then the "
            + "natural generalization over a product group of the given width "
            + "is used. This corresponds to letting each party holding "
            + "multiple standard public keys.";
        final IntField widthField =
            new IntField(ProtocolElGamal.KEYWIDTH, s, 1, 1, 1, null);
        pi.addInfoField(widthField);

        s = "Bit length of challenges in interactive proofs.";
        final IntField vbitlenField =
            new IntField(ProtocolElGamal.VBITLEN, s, 1, 1, 1, MAX_BITLEN);
        pi.addInfoField(vbitlenField);

        s = "Bit length of challenges in non-interactive random-oracle proofs.";
        final IntField vbitlenroField =
            new IntField(ProtocolElGamal.VBITLENRO, s, 1, 1, 1, MAX_BITLEN);
        pi.addInfoField(vbitlenroField);

        s = "Bit length of each component in random vectors used for batching.";
        final IntField ebitlenField =
            new IntField(ProtocolElGamal.EBITLEN, s, 1, 1, 1, MAX_BITLEN);
        pi.addInfoField(ebitlenField);

        s = "Bit length of each component in random vectors used for "
            + "batching in non-interactive random-oracle proofs.";
        final IntField ebitlenroField =
            new IntField(ProtocolElGamal.EBITLENRO, s, 1, 1, 1, MAX_BITLEN);
        pi.addInfoField(ebitlenroField);

        s = "Pseudo random generator used to derive random vectors for "
            + "batchingfrom "
            + "jointly generated seeds. This can be \"SHA-256\", "
            + "\"SHA-384\", or \"SHA-512\", in which case "
            + "com.verificatum.crypto.PRGHeuristic is instantiated based on "
            + "this hashfunction, or it can be an instance of "
            + "com.verificatum.crypto.PRG. WARNING! This field "
            + "is not validated syntactically.";
        pi.addInfoField(new StringField(ProtocolElGamal.PRG, s, 1, 1));

        s = "Hashfunction used to implement random oracles. It can be "
            + "one of the strings \"SHA-256\", \"SHA-384\", or \"SHA-512\", "
            + "in which case com.verificatum.crypto.HashfunctionHeuristic is "
            + "instantiated, or an instance of "
            + "com.verificatum.crypto.Hashfunction. Random oracles "
            + "with various output lengths are then implemented, using the "
            + "given hashfunction, in com.verificatum.crypto.RandomOracle."
            + "\n"
            + "WARNING! Do not change the default unless you know exactly what "
            + "you are doing. This field is not validated syntactically.";
        pi.addInfoField(new StringField(ProtocolElGamal.ROHASH, s, 1, 1));

        s = "Determines if the proofs of correctness of an execution are "
            + "interactive or non-interactive. "
            + "Legal valus are \"interactive\" or \"noninteractive\".";
        final StringField corrField =
            new StringField(ProtocolElGamal.CORR, s, 1, 1).
            setPattern("interactive|noninteractive");
        pi.addInfoField(corrField);
    }

    @Override
    public void addDefault(final ProtocolInfo pi) {
        super.addDefault(pi);
        try {
            pi.addValue(ProtocolElGamal.PGROUP, ProtocolDefaults.PGroup());
            pi.addValue(ProtocolElGamal.KEYWIDTH, 1);
            pi.addValue(ProtocolElGamal.VBITLEN,
                        ProtocolDefaults.SEC_PARAM_CHALLENGE);
            pi.addValue(ProtocolElGamal.VBITLENRO,
                        ProtocolDefaults.SEC_PARAM_CHALLENGE_RO);
            pi.addValue(ProtocolElGamal.EBITLEN,
                        ProtocolDefaults.SEC_PARAM_BATCH);
            pi.addValue(ProtocolElGamal.EBITLENRO,
                        ProtocolDefaults.SEC_PARAM_BATCH_RO);
            pi.addValue(ProtocolElGamal.PRG, ProtocolDefaults.PRG());
            pi.addValue(ProtocolElGamal.ROHASH,
                        ProtocolDefaults.Hashfunction());
            pi.addValue(ProtocolElGamal.CORR, "noninteractive");
        } catch (InfoException ie) {
            throw new ProtocolError("Failed to add default value!", ie);
        }
    }

    @Override
    public void addPrivateInfo(final PrivateInfo pi) {
        super.addPrivateInfo(pi);

        String s;

        s = "Determines the key generation algorithm used to generate "
            + "keys for the CCA2-secure cryptosystem with labels used in "
            + "subprotocols. An instance of "
            + "com.verificatum.crypto.CryptoKeyGen. WARNING! This field "
            + "is not validated syntactically.";
        pi.addInfoField(new StringField(ProtocolElGamal.KEYGEN, s, 1, 1));

        s = "Determines if arrays of group/field elements and integers are "
            + "stored in (possibly virtual) RAM or on file. The latter is "
            + "only slighly slower and can accomodate larger arrays "
            + "(\"ram\" or \"file\").";
        final StringField arraysField =
            new StringField(ProtocolElGamal.ARRAYS, s, 1, 1).
            setPattern("ram|file");
        pi.addInfoField(arraysField);

        pi.addInfoField(new StringField(ProtocolElGamal.NIZKP,
                                        NIZKP_DESCRIPTION, 1, 1));
    }

    @Override
    public void addDefault(final PrivateInfo pi,
                           final ProtocolInfo pri,
                           final RandomSource rs) {
        super.addDefault(pi, pri, rs);
        try {
            pi.addValue(ProtocolElGamal.KEYGEN,
                        ProtocolDefaults.CryptoKeyGen());
            pi.addValue(ProtocolElGamal.ARRAYS, ProtocolDefaults.ARRAYS);
            pi.addValue(ProtocolElGamal.NIZKP, ProtocolDefaults.NIZKP);
        } catch (InfoException ie) {
            throw new ProtocolError("Failed to add default value!", ie);
        }
    }
}
