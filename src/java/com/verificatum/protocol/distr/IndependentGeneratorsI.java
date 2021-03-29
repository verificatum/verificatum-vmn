
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

package com.verificatum.protocol.distr;

import java.io.File;

import com.verificatum.arithm.LargeInteger;
import com.verificatum.arithm.ArithmFormatException;
import com.verificatum.arithm.PGroup;
import com.verificatum.arithm.PGroupElementArray;
import com.verificatum.arithm.PRingElementArray;
import com.verificatum.eio.ByteTreeReader;
import com.verificatum.eio.ByteTreeReaderF;
import com.verificatum.protocol.elgamal.ProtocolElGamal;
import com.verificatum.ui.Log;


/**
 * Generates a list of independent generators, i.e., a list of
 * generators for which finding any non-trivial representation of the
 * unit element in the group implies that the discrete logarithm
 * assumption is violated.
 *
 * @author Douglas Wikstrom
 */
public final class IndependentGeneratorsI extends ProtocolElGamal
    implements IndependentGenerators {

    /**
     * Creates an instance of the protocol.
     *
     * @param sid Session identifier of the created instance.
     * @param protocol Protocol which invokes the created instance.
     */
    public IndependentGeneratorsI(final String sid,
                                  final ProtocolElGamal protocol) {
        super(sid, protocol);
    }

    /**
     * Compute product of parts of generators.
     *
     * @param size Number of elements in arrays.
     * @param generatorsParts Parts of generators.
     * @param log Logging context.
     *
     * @return Product of parts.
     */
    protected PGroupElementArray
        mulGeneratorsParts(final int size,
                           final PGroupElementArray[] generatorsParts,
                           final Log log) {

        final PGroup pGroup = generatorsParts[1].getPGroup();

        log.info("Combine generators of all parties.");
        PGroupElementArray generatorsPartsProd =
            pGroup.toElementArray(size, pGroup.getONE());

        for (int l = 1; l <= threshold; l++) {
            final PGroupElementArray tmp = generatorsPartsProd;
            generatorsPartsProd = generatorsPartsProd.mul(generatorsParts[l]);
            tmp.free();
        }
        return generatorsPartsProd;
    }

    /**
     * Reads the independent generators.
     *
     * @param pGroup Group containing the independent parameters.
     * @param file File expected to contain the independent parameters.
     * @param size Number of independent parameters.
     * @param log Logging context.
     * @return Independent generators.
     */
    private PGroupElementArray readIndependentGenerators(final PGroup pGroup,
                                                         final File file,
                                                         final int size,
                                                         final Log log) {

        log.info("Independent generators exists on file.");
        final Log tempLog = log.newChildLog();

        tempLog.info("Read generators.");
        final ByteTreeReader btr = new ByteTreeReaderF(file);
        final PGroupElementArray generators =
            pGroup.unsafeToElementArray(size, btr);
        btr.close();

        return generators;
    }

    /**
     * Exchange parts of the independent generators.
     *
     * @param pGroup Group containing parts of the independent
     * parameters.
     * @param generatorsParts Parts of the independent generators.
     * @param size Number of independent parameters.
     * @param threshold Number of parties that must be corrupted to
     * violate security of this protocol.
     * @param log Logging context.
     */
    private void publishAndReadParts(final PGroup pGroup,
                                     final PGroupElementArray[] generatorsParts,
                                     final int size,
                                     final int threshold,
                                     final Log log) {

        for (int l = 1; l <= threshold; l++) {

            if (l == j) {

                log.info("Publish generator parts.");
                bullBoard.publish("GeneratorsPart",
                                  generatorsParts[j].toByteTree(),
                                  log);
            } else {

                // Try to read and parse
                log.info("Read generator parts of " + ui.getDescrString(l)
                         + ".");

                ByteTreeReader btr = null;
                try {

                    btr = bullBoard.waitFor(l, "GeneratorsPart", log);
                    generatorsParts[l] = pGroup.toElementArray(size, btr);

                } catch (final ArithmFormatException afe) {
                    log.info("Failed, setting to one-array.");
                    generatorsParts[l] =
                        pGroup.toElementArray(size, pGroup.getONE());
                } finally {
                    if (btr != null) {
                        btr.close();
                    }
                }
            }
        }
    }

    /**
     * Exchange commitments.
     *
     * @param basic Basic functionality of this protocol.
     * @param threshold Number of parties that must be corrupted to
     * violate security of this protocol.
     * @param log Logging context.
     */
    private void
        publishAndSetCommitments(final IndependentGeneratorsBasicI basic,
                                 final int threshold,
                                 final Log log) {

        for (int l = 1; l <= threshold; l++) {

            if (l == j) {

                log.info("Publish commitment.");
                bullBoard.publish("Commitment",
                                  basic.commit(randomSource),
                                  log);

            } else {

                // Try to read and parse
                log.info("Read commitment of " + ui.getDescrString(l) + ".");

                final ByteTreeReader btr =
                    bullBoard.waitFor(l, "Commitment", log);

                basic.setCommitment(l, btr);
                btr.close();

            }
        }
    }

    // Documented in IndependentGenerators.java

    @Override
    public PGroupElementArray generate(final Log log,
                                       final PGroup pGroup,
                                       final int size) {

        log.info("Generate independent generators.");
        final Log tempLog = log.newChildLog();

        final File igFile = getFile("IndependentGenerators");
        if (igFile.exists()) {
            return readIndependentGenerators(pGroup, igFile, size, tempLog);
        }

        // Make room for generator parts.
        final PGroupElementArray[] generatorsParts =
            new PGroupElementArray[threshold + 1];

        // Generate our generator parts.
        PRingElementArray exponents = null;
        if (j <= threshold) {

            tempLog.info("Generate random exponents.");
            exponents = pGroup.getPRing().randomElementArray(size,
                                                             randomSource,
                                                             rbitlen);

            // Compute generators part.
            tempLog.info("Compute generators parts.");
            generatorsParts[j] = pGroup.getg().exp(exponents);

        }

        // Collect generators parts.
        tempLog.info("Collect generators parts.");

        // Publish our parts and read the other's.
        publishAndReadParts(pGroup, generatorsParts, size, threshold, log);

        final IndependentGeneratorsBasicI basic =
            new IndependentGeneratorsBasicI(j,
                                            threshold,
                                            ebitlen,
                                            rbitlen,
                                            prg);

        // Combine parts.
        PGroupElementArray generators =
            mulGeneratorsParts(size, generatorsParts, tempLog);

        // Initialize the instance.
        basic.setInstance(pGroup.getg(),
                          generatorsParts,
                          exponents,
                          generators);

        // Generate seed for batching.
        tempLog.info("Generate seed for batching.");
        Log tempLog2 = tempLog.newChildLog();

        final byte[] prgSeed =
            coins.getCoinBytes(tempLog2, 8 * prg.minNoSeedBytes(), rbitlen);
        basic.setBatchVector(prgSeed);

        // Collect commitments.
        tempLog.info("Collect commitments.");

        // Publish our parts and read the other's.
        publishAndSetCommitments(basic, threshold, log);

        // Generate challenge.
        tempLog.info("Generate challenge.");
        tempLog2 = tempLog.newChildLog();
        final byte[] challengeBytes =
            coins.getCoinBytes(tempLog2, vbitlen, rbitlen);
        final LargeInteger integerChallenge =
            LargeInteger.toPositive(challengeBytes);
        basic.setChallenge(integerChallenge);

        // Collect replies parts.
        tempLog.info("Collect replies.");
        tempLog2 = tempLog.newChildLog();

        // Publish our parts and read the other's.
        for (int l = 1; l <= threshold; l++) {

            if (l == j) {

                tempLog2.info("Publish reply.");
                bullBoard.publish("Reply", basic.reply(), tempLog);

            } else {

                // Try to read and parse
                tempLog2.info("Read replies of " + ui.getDescrString(l) + ".");

                final ByteTreeReader btr =
                    bullBoard.waitFor(l, "Reply", tempLog);
                basic.setReply(l, btr);
                btr.close();

            }
        }

        // Verify combined commitment.
        tempLog.info("Verify combined statement.");

        if (basic.verify()) {

            tempLog.info("Accepted proof.");

        } else {

            tempLog.info("Rejected proof.");
            tempLog.info("Verifying proofs separately.");
            tempLog2 = tempLog.newChildLog();

            for (int l = 1; l <= threshold; l++) {

                if (l != j) {

                    tempLog2.info("Verify proof of " + ui.getDescrString(l)
                                  + ".");
                    final boolean verd = basic.verify(l);
                    if (verd) {
                        tempLog2.info("Accepted proof.");
                    } else {
                        tempLog2.info("Rejected proof.");
                        tempLog2.info("Replacing generators parts by ones.");
                        generatorsParts[l] =
                            pGroup.toElementArray(size, pGroup.getONE());
                    }
                }
            }

            generators.free();
            generators = mulGeneratorsParts(size, generatorsParts, tempLog);
        }

        generators.toByteTree().unsafeWriteTo(igFile);

        return generators;
    }
}
