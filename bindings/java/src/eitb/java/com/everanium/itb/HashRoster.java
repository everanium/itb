// Diagnostic registry iteration for the eitb CLI.
//
// The binding library deliberately exposes no primitive enumeration;
// this bridge class lives in the library package (shipped only inside
// the eitb tool jar, never in the library jar) so the CLI can reach
// the package-private JNI declarations and print the shipped roster.

package com.everanium.itb;

/** eitb-only bridge over the hash-registry iteration exports. */
public final class HashRoster {

    private HashRoster() {
    }

    /** Prints the shipped hash primitive roster to stdout. */
    public static void print() {
        int count = Native.hashCount();
        for (int i = 0; i < count; i++) {
            final int index = i;
            String name = Native.readCString((out, cap, outLen) ->
                    Native.hashName(index, out, cap, outLen));
            int width = Native.hashWidth(i);
            System.out.printf("%2d  %-12s %d bits%n", i, name, width);
        }
    }
}
