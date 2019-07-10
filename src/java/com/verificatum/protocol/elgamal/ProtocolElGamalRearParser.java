
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.verificatum.protocol.ProtocolFormatException;


/**
 * Parser of format passed to {@link ProtocolElGamalRearTool}.
 *
 * @author Douglas Wikstrom
 */
public final class ProtocolElGamalRearParser {

    /**
     * Parses a string description of a non-empty integer interval
     * [s,e). An interval is represented by a string of the form
     * "s-e", where 0 <= s < e, i.e., s is the inclusive starting
     * index and e is the exclusive ending index.
     *
     * @param intervalString String description of an interval.
     * @return Interval.
     * @throws ProtocolFormatException If parsing fails.
     */
    public ProtocolElGamalRearInterval
        parseInterval(final String intervalString)
        throws ProtocolFormatException {

        final String e = "Malformed interval! (" + intervalString + ")";
        try {

            final String[] bounds = intervalString.split("-");

            if (bounds.length != 2) {
                throw new ProtocolFormatException(e);
            }

            final int start = Integer.parseInt(bounds[0]);
            final int end = Integer.parseInt(bounds[1]);

            if (start < 0 || start >= end) {
                throw new ProtocolFormatException(e);
            } else {
                return new ProtocolElGamalRearInterval(start, end);
            }

        } catch (NumberFormatException nfe) {
            throw new ProtocolFormatException(e, nfe);
        }
    }

    /**
     * Parses a list of intervals represented as a string of the form
     * "A:B:C:...", where A,B,C... are of the form "s-e", i.e., valid
     * inputs to {@link #parseInterval}.
     *
     * @param intervalsString String representation of a list of intervals.
     * @return List of intervals.
     * @throws ProtocolFormatException If parsing fails.
     */
    public List<ProtocolElGamalRearInterval>
        parseIntervals(final String intervalsString)
        throws ProtocolFormatException {

        final List<ProtocolElGamalRearInterval> res =
            new ArrayList<ProtocolElGamalRearInterval>();

        final String[] intervalsStrings = intervalsString.split(":");

        if (intervalsStrings.length == 0) {
            throw new ProtocolFormatException("No interval is given!");
        }

        for (int i = 0; i < intervalsStrings.length; i++) {
            res.add(parseInterval(intervalsStrings[i]));
        }

        return res;
    }

    /**
     * Parses a string description of an integer interval [s,e) and
     * returns the integers as a list. An interval is represented by
     * "s-e", where 0 <= s < e, or if it is a single integer simply s
     * (instead of "s-e", where e=s+1).
     *
     * @param intervalString String description of an interval.
     * @return List of non-negative consecutive integers.
     * @throws ProtocolFormatException If parsing fails.
     */
    public List<Integer> parseIntervalToSequence(final String intervalString)
        throws ProtocolFormatException {

        final String e = "Malformed interval! (" + intervalString + ")";

        final List<Integer> res = new ArrayList<Integer>();

        final int middle = intervalString.indexOf("-");

        try {

            // Single integer.
            if (middle == -1) {

                res.add(Integer.parseInt(intervalString));

            // Interval.
            } else {

                final ProtocolElGamalRearInterval interval =
                    parseInterval(intervalString);

                for (int i = interval.start; i < interval.end; i++) {
                    res.add(i);
                }
            }
        } catch (NumberFormatException nfe) {
            throw new ProtocolFormatException(e, nfe);
        }
        return res;
    }

    /**
     * Parse a string representation of a list of positions captured
     * by an expression of the form "(x,y)" where x and y are of the
     * forms "a" or "s-e" for integers 0 <= a or 0 <= s < e respectively.
     *
     * @param posString String representation of list of positions.
     * @param strict Determines if x and y must be of the form "s" or
     * not.
     * @return List of positions identifying a group element (or a
     * list of group elements) and a component (or list of components)
     * thereof.
     * @throws ProtocolFormatException If parsing fails.
     */
    public List<ProtocolElGamalRearPosition>
        parsePositions(final String posString,
                       final boolean strict)
        throws ProtocolFormatException {

        final String e = "Malformed position string! (" + posString + ")";

        final int endPos = posString.length();

        if (endPos < 5
            || posString.charAt(0) != '('
            || posString.charAt(endPos - 1) != ')') {

            throw new ProtocolFormatException(e);
        }

        final String[] coeffs = posString.substring(1, endPos - 1).split(",");

        if (coeffs.length != 2) {
            throw new ProtocolFormatException(e);
        }

        final List<Integer> rows = parseIntervalToSequence(coeffs[0]);
        final List<Integer> columns = parseIntervalToSequence(coeffs[1]);

        if (strict) {
            if (rows.size() != 1) {
                final String er = e + " Invalid index! (" + coeffs[0] + ")";
                throw new ProtocolFormatException(er);
            }
            if (columns.size() != 1) {
                final String ec = e + " Invalid index! (" + coeffs[1] + ")";
                throw new ProtocolFormatException(ec);
            }
        }

        final List<ProtocolElGamalRearPosition> res =
            new ArrayList<ProtocolElGamalRearPosition>();
        for (final int row : rows) {
            for (final int column : columns) {
                res.add(new ProtocolElGamalRearPosition(row, column));
            }
        }
        return res;
    }

    /**
     * Returns a list of positions identifying components of group
     * elements (or components of group element arrays) to
     * combine. The input is of the form "AxBxCx...", where
     * A,B,C,.. are valid inputs to {@link #parsePositions}.
     *
     * @param sourceString String representation of a list of positions
     * identifying group elements (or arrays of group elements) to
     * combine.
     * @return List of positions identifying components of group
     * elements (or components of group element arrays) to combine.
     * @throws ProtocolFormatException If parsing fails.
     */
    public List<ProtocolElGamalRearPosition>
        parseSource(final String sourceString)
        throws ProtocolFormatException {

        final List<ProtocolElGamalRearPosition> res =
            new ArrayList<ProtocolElGamalRearPosition>();

        final String[] positions = sourceString.split("x");
        for (int i = 0; i < positions.length; i++) {
            res.addAll(parsePositions(positions[i], false));
        }
        return res;
    }

    /**
     * Returns a list of lists of positions identifying group elements
     * (or arrays of group elements) to combine. The input is of the
     * form "A:B:C:...", where A,B,C... are valid inputs to {@link
     * #parseSource}.
     *
     * @param formatString String representation of list of lists of
     * positions identifying group elements (or arrays of group
     * elements) to combine.
     * @return List of lists of positions identifying components of
     * group elements (or components of group element arrays) to
     * combine.
     * @throws ProtocolFormatException If parsing fails.
     */
    public List<List<ProtocolElGamalRearPosition>>
        parseFormat(final String formatString)
        throws ProtocolFormatException {

        final String[] sources = formatString.split(":");

        final List<List<ProtocolElGamalRearPosition>> res =
            new ArrayList<List<ProtocolElGamalRearPosition>>();

        for (int i = 0; i < sources.length; i++) {
            res.add(parseSource(sources[i]));
        }
        return res;
    }

    /**
     * Parses a colon separated list of positive integer widths of
     * product groups.
     *
     * @param widthString String representation of all widths.
     * @return Array of positive integers.
     * @throws ProtocolFormatException If parsing fails.
     */
    public int[] parseWidths(final String widthString)
        throws ProtocolFormatException {

        final String[] widthStrings = widthString.split(":");
        final int[] widths = new int[widthStrings.length];

        if (widths.length == 0) {
            throw new ProtocolFormatException("No widths!");
        }

        for (int i = 0; i < widths.length; i++) {
            try {

                widths[i] = Integer.parseInt(widthStrings[i]);
                if (widths[i] < 1) {
                    throw new ProtocolFormatException("Non-positive width!");
                }

            } catch (NumberFormatException nfe) {
                final String e =
                    "Failed to parse width! (" + widthStrings[i] + ")";
                throw new ProtocolFormatException(e, nfe);
            }
        }
        return widths;
    }

    /**
     * Returns a subarray of filenames.
     *
     * @param filenames List of all filenames.
     * @param start Starting index.
     * @param end Ending index.
     * @return Array of input filenames.
     * @throws ProtocolFormatException If the number of input
     * filenames is invalid.
     */
    public String[] getFilenames(final String[] filenames,
                                 final int start,
                                 final int end)
        throws ProtocolFormatException {

        if (start < 0 || start >= end || end >= filenames.length) {

            final String f =
                "The starting and ending indexes (%d and %d) are not valid "
                + "for an array of filenames of length %d!";
            final String e = String.format(f, start, end, filenames.length);
            throw new ProtocolFormatException(e);
        }
        return Arrays.copyOfRange(filenames, start, end);
    }

    /**
     * Pretty string representation of a format. This is used for
     * debugging.
     *
     * @param format Format for the output.
     * @return Pretty string representation of all widths.
     */
    public String
        prettyFormat(final List<List<ProtocolElGamalRearPosition>> format) {

        final StringBuilder sb = new StringBuilder();

        for (final List<ProtocolElGamalRearPosition> row : format) {

            sb.append(row.get(0).toString());
            for (int i = 1; i < row.size(); i++) {
                sb.append('x');
                sb.append(row.get(i).toString());
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
