
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
