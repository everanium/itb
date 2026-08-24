// Hash-registry enumeration for the eitb `hashes` diagnostic.
//
// Deliberately declared in the Java binding's package: the registry
// iteration surface (hashCount / hashName / hashWidth) is
// package-private in the Java binding — the library itself exposes
// no primitive enumeration — and JVM package-level access spans jars
// under one classloader, mirroring the C# binding's
// InternalsVisibleTo arrangement for the same diagnostic.

package com.everanium.itb

/** One registry row: index, name, and native width in bits. */
data class HashEntry(val index: Int, val name: String, val widthBits: Int)

/** Reads the shipped hash primitive roster through the Java
 * binding's internal FFI surface. */
fun hashRoster(): List<HashEntry> =
    (0 until Native.hashCount()).map { i ->
        val name = Native.readCString { out, cap, outLen -> Native.hashName(i, out, cap, outLen) }
        HashEntry(i, name, Native.hashWidth(i))
    }
