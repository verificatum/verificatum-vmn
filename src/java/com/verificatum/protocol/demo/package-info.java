
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

/**
 *
 * This package gives a unified way to demonstrate and unit test
 * cryptographic protocols. The main things that distinguishes a
 * demonstration from a real execution are the following:
 *
 * <ol>
 *
 * <li> Each party is executed as a {@link java.lang.Runnable}. Thus,
 * all parties are simulated locally within a single JVM.
 *
 * <li> The configuration files used by a party are typically
 * generated automatically, based on the options provided to the
 * demonstrator.
 *
 * </ol>

 * To demonstrate an existing protocol, the programmer must implement
 * the interface {@link
 * com.verificatum.protocol.demo.DemoProtocolElGamalFactory}. This
 * interface allows {@link com.verificatum.protocol.demo.Demo} to set up
 * and execute a demonstration.
 */

package com.verificatum.protocol.demo;
