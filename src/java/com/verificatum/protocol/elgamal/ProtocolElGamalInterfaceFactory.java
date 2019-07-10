
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

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.verificatum.protocol.ProtocolFormatException;
import com.verificatum.ui.info.InfoGenerator;


/**
 * Factory for interfaces of an El Gamal protocol. This defines the
 * format of: the public key that is used by senders, the input
 * ciphertexts, and the output plaintexts.
 *
 * @author Douglas Wikstrom
 */
public class ProtocolElGamalInterfaceFactory {

    /**
     * Error used when attempting to instantiating a non-existent
     * class.
     */
    public static final String UNKNOWN_INTERFACE = "Unknown interface!";

    /**
     * Map of short nick names to full class names of interfaces.
     */
    static ConcurrentMap<String, String> shortNames =
        new ConcurrentHashMap<String, String>();

    static {
        put("raw", "ProtocolElGamalInterfaceRaw");
        put("native", "ProtocolElGamalInterfaceNative");
        put("json", "ProtocolElGamalInterfaceJSON");
        put("jsondecode", "ProtocolElGamalInterfaceJSONDecode");
    }

    /**
     * Store a full class name under the given nick.
     *
     * @param shortName Short nick name of interface.
     * @param shortClassname Short class name.
     */
    private static void put(final String shortName,
                            final String shortClassname) {
        shortNames.put(shortName,
                       "com.verificatum.protocol.elgamal." + shortClassname);
    }

    /**
     * Returns the named interface.
     *
     * @param interfaceName Name of interface.
     * @return Requested interface.
     *
     * @throws ProtocolFormatException If the input is not the short
     * name of an interface class.
     */
    public ProtocolElGamalInterface getInterface(final String interfaceName)
        throws ProtocolFormatException {

        String currentIN = interfaceName;

        if (shortNames.containsKey(currentIN)) {
            currentIN = shortNames.get(currentIN);
        }

        // If we don't recognize the string we assume that the user
        // has implemented his own interface class.
        try {

            final Class<?> klass = Class.forName(currentIN);
            final Constructor<?> con = klass.getConstructor(new Class[0]);
            final Object obj = con.newInstance();

            if (obj instanceof ProtocolElGamalInterface) {
                return (ProtocolElGamalInterface) obj;
            } else {
                throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                                  + currentIN + ")");
            }

        } catch (final InvocationTargetException ite) {
            throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                              + currentIN + ")", ite);
        } catch (final IllegalAccessException iae) {
            throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                              + currentIN + ")", iae);
        } catch (final ClassNotFoundException cnfe) {
            throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                              + currentIN + ")", cnfe);
        } catch (final NoSuchMethodException nsme) {
            throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                              + currentIN + ")", nsme);
        } catch (final InstantiationException ie) {
            throw new ProtocolFormatException(UNKNOWN_INTERFACE + " ("
                                              + currentIN + ")", ie);
        }
    }

    /**
     * Return the info generator of this factory.
     *
     * @param protocolInfoFile Protocol info file.
     * @return Info generator.
     *
     * @throws ProtocolFormatException If this class is instantiated
     * and this method is used, i.e., only {@link
     * #getInterface(String)} may be used if this class is
     * instantiated, whereas subclasses are expected to implement this
     * method.
     */
    public InfoGenerator getGenerator(final File protocolInfoFile)
        throws ProtocolFormatException {

        throw new ProtocolFormatException("Must be implemented by subclass!");
    }
}
