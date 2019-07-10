
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

import java.lang.reflect.*;

/**
 * Implements a class that tries to load a Java class of a given
 * version. This is used by the configure script.
 *
 * @author Douglas Wikstrom
 */
public class TestLoadJar {

    @SuppressWarnings("unchecked")
    public static void main(String[] args) {

        String className = args[0];
	Class klass = null;

	try {
	    klass = Class.forName(className);
	} catch (ClassNotFoundException cnfe) {
	    System.out.println("Cannot locate the class " + className + "!");
	} catch (SecurityException se) {
	    System.out.println("Not allowed to load the native library needed "
                               + "by " + className + " to run in native mode!");
	} catch (UnsatisfiedLinkError ule) {
	    System.out.println("Missing native library needed by "
                               + className + "!");
	} catch (IllegalArgumentException iare) {
	    System.out.println("This is a bug in the building system!");
	}

        if (klass != null) {
            final String ev = args[1];
            final String av = klass.getPackage().getSpecificationVersion();

            if (!av.equals(ev)) {
                System.out.println("Wrong version number ("
                                   + av + "), requires " + ev + "!");
            }
        }
    }
}
