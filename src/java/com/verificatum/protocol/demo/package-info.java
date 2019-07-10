
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
