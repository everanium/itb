// Typed view of the Triple profile record — the JSON object that
// ITB_Triple_Inspect / ITB_Triple_Lookup emit, ITB_Triple_Register
// accepts, and the session blob carries in its wrap-layer.

package com.everanium.itb;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A Triple Pipeline profile record.
 *
 * <p>The record is a plain data holder plus a JSON codec for the
 * fourteen keys of the wire object ({@code name}, {@code mode},
 * {@code width}, {@code hash}, {@code hashes}, {@code keybits},
 * {@code mac}, {@code tagstub}, {@code chunk}, {@code wrapper},
 * {@code outer}, {@code parallax}, {@code palette}, {@code segment}).
 * No semantic validation happens on the Java side — every field rule
 * (mode names, width / hash agreement, key sizes, palette shape,
 * reserved name prefixes) is enforced by Go at
 * {@link Pipeline#register} / {@link Pipeline#load} time and surfaces
 * as an {@link ItbException}. Primitive / MAC / cipher names are
 * opaque strings.</p>
 *
 * <p>Encoding mirrors the Go codec: {@code mode}, {@code width},
 * {@code keybits}, {@code wrapper}, {@code parallax} are always
 * emitted; an empty string, zero integer, or empty array is omitted.
 * {@code hashes} carries either nothing or exactly eight slot names
 * in the order {@code [noise, lock, data1, data2, data3, start1,
 * start2, start3]}.</p>
 */
public final class Profile {

    private String name = "";
    private String mode = "";
    private int width;
    private String hash = "";
    private List<String> hashes = Collections.emptyList();
    private int keyBits;
    private String mac = "";
    private int tagStub;
    private int chunk;
    private boolean wrapper;
    private String outer = "";
    private boolean parallax;
    private List<String> palette = Collections.emptyList();
    private int segment;

    /** An empty record; populate through the fluent setters. */
    public Profile() {
    }

    /** Registry handle ({@code name}); empty on an anonymous record. */
    public String name() {
        return name;
    }

    /** Pipeline mode ({@code mode}), e.g. {@code streaming-aead}. */
    public String mode() {
        return mode;
    }

    /** Seed width in bits ({@code width}). */
    public int width() {
        return width;
    }

    /** Uniform inner hash ({@code hash}); empty on a mixed profile. */
    public String hash() {
        return hash;
    }

    /** Eight-slot mixed constellation ({@code hashes}); empty on a
     * uniform profile. Unmodifiable. */
    public List<String> hashes() {
        return hashes;
    }

    /** Key material size in bits ({@code keybits}). */
    public int keyBits() {
        return keyBits;
    }

    /** MAC name ({@code mac}); empty on a No MAC profile. */
    public String mac() {
        return mac;
    }

    /** Tag stub size ({@code tagstub}); 0 when absent. */
    public int tagStub() {
        return tagStub;
    }

    /** Streaming chunk size ({@code chunk}); 0 when absent. */
    public int chunk() {
        return chunk;
    }

    /** Whether the wrapper layer is on ({@code wrapper}). */
    public boolean wrapper() {
        return wrapper;
    }

    /** Outer cipher name ({@code outer}); empty when absent. */
    public String outer() {
        return outer;
    }

    /** Whether the parallax layer is on ({@code parallax}). */
    public boolean parallax() {
        return parallax;
    }

    /** Parallax palette ({@code palette}); empty when absent.
     * Unmodifiable. */
    public List<String> palette() {
        return palette;
    }

    /** Parallax segment size ({@code segment}); 0 when absent. */
    public int segment() {
        return segment;
    }

    public Profile name(String value) {
        this.name = value == null ? "" : value;
        return this;
    }

    public Profile mode(String value) {
        this.mode = value == null ? "" : value;
        return this;
    }

    public Profile width(int value) {
        this.width = value;
        return this;
    }

    public Profile hash(String value) {
        this.hash = value == null ? "" : value;
        return this;
    }

    /** Sets the mixed constellation; pass nothing to clear. */
    public Profile hashes(String... values) {
        this.hashes = values == null ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(Arrays.asList(values)));
        return this;
    }

    public Profile keyBits(int value) {
        this.keyBits = value;
        return this;
    }

    public Profile mac(String value) {
        this.mac = value == null ? "" : value;
        return this;
    }

    public Profile tagStub(int value) {
        this.tagStub = value;
        return this;
    }

    public Profile chunk(int value) {
        this.chunk = value;
        return this;
    }

    public Profile wrapper(boolean value) {
        this.wrapper = value;
        return this;
    }

    public Profile outer(String value) {
        this.outer = value == null ? "" : value;
        return this;
    }

    public Profile parallax(boolean value) {
        this.parallax = value;
        return this;
    }

    /** Sets the parallax palette; pass nothing to clear. */
    public Profile palette(String... values) {
        this.palette = values == null ? Collections.emptyList()
                : Collections.unmodifiableList(new ArrayList<>(Arrays.asList(values)));
        return this;
    }

    public Profile segment(int value) {
        this.segment = value;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Profile)) {
            return false;
        }
        Profile p = (Profile) o;
        return width == p.width && keyBits == p.keyBits && tagStub == p.tagStub
                && chunk == p.chunk && wrapper == p.wrapper && parallax == p.parallax
                && segment == p.segment && name.equals(p.name) && mode.equals(p.mode)
                && hash.equals(p.hash) && hashes.equals(p.hashes) && mac.equals(p.mac)
                && outer.equals(p.outer) && palette.equals(p.palette);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, mode, width, hash, hashes, keyBits, mac, tagStub,
                chunk, wrapper, outer, parallax, palette, segment);
    }

    @Override
    public String toString() {
        return "Profile" + toJson();
    }

    // ── JSON codec ──────────────────────────────────────────────────

    /** Renders the record as the wire JSON object. */
    public String toJson() {
        StringBuilder sb = new StringBuilder(256).append('{');
        boolean[] first = {true};
        if (!name.isEmpty()) {
            key(sb, first, "name").append(quote(name));
        }
        key(sb, first, "mode").append(quote(mode));
        key(sb, first, "width").append(width);
        if (!hash.isEmpty()) {
            key(sb, first, "hash").append(quote(hash));
        }
        if (!hashes.isEmpty()) {
            key(sb, first, "hashes");
            array(sb, hashes);
        }
        key(sb, first, "keybits").append(keyBits);
        if (!mac.isEmpty()) {
            key(sb, first, "mac").append(quote(mac));
        }
        if (tagStub != 0) {
            key(sb, first, "tagstub").append(tagStub);
        }
        if (chunk != 0) {
            key(sb, first, "chunk").append(chunk);
        }
        key(sb, first, "wrapper").append(wrapper);
        if (!outer.isEmpty()) {
            key(sb, first, "outer").append(quote(outer));
        }
        key(sb, first, "parallax").append(parallax);
        if (!palette.isEmpty()) {
            key(sb, first, "palette");
            array(sb, palette);
        }
        if (segment != 0) {
            key(sb, first, "segment").append(segment);
        }
        return sb.append('}').toString();
    }

    /** Decodes a wire JSON object into a record. Unknown keys are
     * ignored here; the Go side is the strict decoder. */
    public static Profile fromJson(String json) {
        Json p = new Json(json);
        Profile out = new Profile();
        p.expect('{');
        if (p.peek() == '}') {
            p.next();
            p.end();
            return out;
        }
        while (true) {
            String k = p.string();
            p.expect(':');
            switch (k) {
                case "name":
                    out.name = p.string();
                    break;
                case "mode":
                    out.mode = p.string();
                    break;
                case "width":
                    out.width = p.integer();
                    break;
                case "hash":
                    out.hash = p.string();
                    break;
                case "hashes":
                    out.hashes = Collections.unmodifiableList(p.strings());
                    break;
                case "keybits":
                    out.keyBits = p.integer();
                    break;
                case "mac":
                    out.mac = p.string();
                    break;
                case "tagstub":
                    out.tagStub = p.integer();
                    break;
                case "chunk":
                    out.chunk = p.integer();
                    break;
                case "wrapper":
                    out.wrapper = p.bool();
                    break;
                case "outer":
                    out.outer = p.string();
                    break;
                case "parallax":
                    out.parallax = p.bool();
                    break;
                case "palette":
                    out.palette = Collections.unmodifiableList(p.strings());
                    break;
                case "segment":
                    out.segment = p.integer();
                    break;
                default:
                    p.skip();
                    break;
            }
            char c = p.next();
            if (c == '}') {
                break;
            }
            if (c != ',') {
                throw p.error("expected , or }");
            }
        }
        p.end();
        return out;
    }

    /** Decodes a JSON array of strings (the {@code ITB_Triple_Profiles}
     * output). */
    static List<String> stringsFromJson(String json) {
        Json p = new Json(json);
        List<String> out = p.strings();
        p.end();
        return out;
    }

    static String utf8(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static StringBuilder key(StringBuilder sb, boolean[] first, String k) {
        if (!first[0]) {
            sb.append(',');
        }
        first[0] = false;
        return sb.append('"').append(k).append("\":");
    }

    private static void array(StringBuilder sb, List<String> values) {
        sb.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(quote(values.get(i)));
        }
        sb.append(']');
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.append('"').toString();
    }

    /** Minimal recursive-descent reader for the flat profile object
     * and the profile-name array: strings, integers, booleans, null,
     * and nested arrays / objects (skipped when unexpected). */
    private static final class Json {
        private final String s;
        private int i;

        Json(String s) {
            this.s = s;
        }

        IllegalArgumentException error(String what) {
            return new IllegalArgumentException(
                    "itb: profile JSON: " + what + " at offset " + i);
        }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        char peek() {
            ws();
            if (i >= s.length()) {
                throw error("unexpected end");
            }
            return s.charAt(i);
        }

        char next() {
            char c = peek();
            i++;
            return c;
        }

        void expect(char c) {
            if (next() != c) {
                throw error("expected " + c);
            }
        }

        void end() {
            ws();
            if (i != s.length()) {
                throw error("trailing content");
            }
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    throw error("unterminated string");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (i >= s.length()) {
                    throw error("unterminated escape");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"':
                    case '\\':
                    case '/':
                        sb.append(e);
                        break;
                    case 'b':
                        sb.append('\b');
                        break;
                    case 'f':
                        sb.append('\f');
                        break;
                    case 'n':
                        sb.append('\n');
                        break;
                    case 'r':
                        sb.append('\r');
                        break;
                    case 't':
                        sb.append('\t');
                        break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw error("short \\u escape");
                        }
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw error("bad escape");
                }
            }
        }

        int integer() {
            ws();
            int start = i;
            if (i < s.length() && s.charAt(i) == '-') {
                i++;
            }
            while (i < s.length() && Character.isDigit(s.charAt(i))) {
                i++;
            }
            if (start == i) {
                throw error("expected integer");
            }
            return Integer.parseInt(s.substring(start, i));
        }

        boolean bool() {
            if (s.startsWith("true", i)) {
                i += 4;
                return true;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return false;
            }
            throw error("expected boolean");
        }

        List<String> strings() {
            List<String> out = new ArrayList<>();
            if (peek() == 'n') {
                skip();
                return out;
            }
            expect('[');
            if (peek() == ']') {
                i++;
                return out;
            }
            while (true) {
                out.add(string());
                char c = next();
                if (c == ']') {
                    return out;
                }
                if (c != ',') {
                    throw error("expected , or ]");
                }
            }
        }

        /** Skips one value of any shape. */
        void skip() {
            char c = peek();
            if (c == '"') {
                string();
            } else if (c == '{' || c == '[') {
                char close = c == '{' ? '}' : ']';
                i++;
                if (peek() == close) {
                    i++;
                    return;
                }
                while (true) {
                    if (close == '}') {
                        string();
                        expect(':');
                    }
                    skip();
                    char d = next();
                    if (d == close) {
                        return;
                    }
                    if (d != ',') {
                        throw error("expected , or " + close);
                    }
                }
            } else {
                while (i < s.length() && ",]}".indexOf(s.charAt(i)) < 0
                        && !Character.isWhitespace(s.charAt(i))) {
                    i++;
                }
            }
        }
    }
}
