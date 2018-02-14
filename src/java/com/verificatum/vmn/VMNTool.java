
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

package com.verificatum.vmn;

import java.util.Formatter;
import java.util.Locale;

import com.verificatum.ui.Util;
import com.verificatum.ui.opt.Opt;
import com.verificatum.vcr.VCR;

/*
 * In contrast to most of the source, this file contains several
 * hard-coded names and descriptions. This is needed, since this
 * provides overall descriptions.
 */

/**
 * Command line interface that collects the functionality of all VMN
 * commands under a single umbrella to improve the user experience. It
 * merely provides high level usage information and the ability to
 * execute each listed command indirectly.
 *
 * @author Douglas Wikstrom
 */
public final class VMNTool {

    /**
     * Avoid accidental instantiation.
     */
    private VMNTool() { }

    /**
     * Normal commands.
     */
    static final String NORMAL_COMMANDS = "vog|vmni|vmn|vmnv|vre|vmnc";

    /**
     * Commands used during development and deployment.
     */
    static final String DEVEL_COMMANDS = "vbt|vmnd";

    /**
     * All commands.
     */
    static final String COMMANDS = NORMAL_COMMANDS + "|" + DEVEL_COMMANDS;

    /**
     * Formats paragraph.
     *
     * @param sb Destination.
     * @param command Command to describe.
     * @param description Description of command.
     */
    private static void formatParagraph(final StringBuilder sb,
                                        final String command,
                                        final String description) {
        final Formatter f = new Formatter(sb, Locale.US);

        final String broken = Util.breakLines(description, Opt.LINE_WIDTH - 8);
        final String[] lines = Util.split(broken, "\n");
        f.format(" %-4s - %s", command, lines[0]);
        for (int i = 1; i < lines.length; i++) {
            f.format("%n%5s   %s", "", lines[i]);
        }
        sb.append('\n');
    }

    /**
     * Command line interface to configuration tool.
     *
     * @param args Command line arguments.
     */
    @SuppressWarnings("PMD.CyclomaticComplexity")
    public static void main(final String[] args) {

        if (args.length < 1) {
            System.err.println("Failed to pass wrapper parameters!");
            System.exit(1);
        }
        final String commandName = args[0];

        if (args.length == 2 && "-version".equals(args[1])) {
            System.out.println(VCR.version());
            System.exit(0);
        }

        if (args.length == 2 && "-h".equals(args[1])) {

            final String header =
"Usage:\n"
+ " " + commandName + " -h\n"
+ " " + commandName + " " + NORMAL_COMMANDS + " <params>...\n"
+ " " + commandName + " " + DEVEL_COMMANDS + " <params>...\n"
+ " " + commandName + " -version\n"
+ "\n\n"
+ "Description:"
+ "\n\n"
+ "Executes the provided commands. Each command can be executed on its own "
+ "as well. A brief description of each command follows. Please execute "
+ "any particular command with \"-h\" to get the full usage information."
+ "\n\n";

            final StringBuilder sb = new StringBuilder();
            sb.append(Util.breakLines(header, Opt.LINE_WIDTH));

            formatParagraph(sb, "vog",
"Provides a uniform interface to all primitive objects that can be generated "
+ "and used in initialization files of protocols or as inputs to other calls "
+ "to this tool.");

            formatParagraph(sb, "vmni",
"Generates configuration files for the Verificatum Mix-Net.");

            formatParagraph(sb, "vmn", "Executes the Verificatum Mix-Net.");

            formatParagraph(sb, "vmnv",
"Verifies the overall correctness of an execution of the Verificatum Mix-Net.");

            formatParagraph(sb, "vre",
"Re-arranges inputs and outputs of the mix-net in various ways.");

            formatParagraph(sb, "vmnc",
"Plug-in based tool for converting public keys, ciphertexts, and plaintexts "
+ "from/to custom formats.");

            formatParagraph(sb, "vbt",
"Reads byte tree data and prints it as a nested JSON array or reads data and "
+ "verifies that it is a valid byte tree.");

            formatParagraph(sb, "vmnd",
"Generates demo ciphertexts for the given interface.");

            System.out.println(sb.toString());
            System.exit(0);
        }

        if (args.length == 1 || COMMANDS.indexOf(args[1]) == -1) {
            System.out.println("ERROR: Invalid usage form, please use "
                               + "\"" + commandName
                               + " -h\" for usage information!");
            System.exit(1);
        } else {

            // This indicates to the shell script wrapper that it
            // should drop the name of the command from the command
            // line arguments and execute the command.
            System.exit(2);
        }
    }
}
