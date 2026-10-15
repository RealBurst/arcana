/*
 * Copyright 2026 Stephane Bury
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.stef.arcana.formats.dmg;

import be.stef.arcana.exceptions.ArcanaCorruptedException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal reader of Apple XML property lists, enough for the UDIF resource
 * list: dict (Map), array (List), string / key / integer / real / date
 * (String), data (byte[], base64), true / false (Boolean). The DOCTYPE is
 * skipped and never loaded; entities other than the five predefined ones and
 * the numeric references are kept as text.
 *
 * @author Stef
 * @since 1.5
 */
final class PlistParser {

    private static final int MAX_DEPTH = 64;

    private final String s;
    private int pos;

    private PlistParser(final String s) {
        this.s = s;
    }

    /** Parses the plist document and returns its root value. */
    static Object parse(final String xml) throws ArcanaCorruptedException {
        final PlistParser p = new PlistParser(xml);
        try {
            String tag;
            do {
                tag = p.nextTag();
                if (tag == null) throw new ArcanaCorruptedException("Disk image property list: no <plist> element");
            } while (!tag.startsWith("plist"));
            final String root = p.nextTag();
            if (root == null || root.equals("/plist")) return null;
            return p.value(root, 0);
        } catch (final StringIndexOutOfBoundsException | IllegalArgumentException e) {
            throw new ArcanaCorruptedException("Invalid disk image property list", e);
        }
    }

    /** Next tag name with its attributes (without the angle brackets), skipping text, comments, declarations; null at the end. */
    private String nextTag() throws ArcanaCorruptedException {
        while (true) {
            final int lt = s.indexOf('<', pos);
            if (lt < 0) return null;
            if (s.startsWith("<!--", lt)) {
                final int e = s.indexOf("-->", lt + 4);
                if (e < 0) throw new ArcanaCorruptedException("Invalid disk image property list (comment)");
                pos = e + 3;
                continue;
            }
            final int gt = s.indexOf('>', lt);
            if (gt < 0) throw new ArcanaCorruptedException("Invalid disk image property list (tag)");
            pos = gt + 1;
            if (s.charAt(lt + 1) == '?' || s.charAt(lt + 1) == '!') continue;
            return s.substring(lt + 1, gt).trim();
        }
    }

    private Object value(final String tag, final int depth) throws ArcanaCorruptedException {
        if (depth > MAX_DEPTH) throw new ArcanaCorruptedException("Disk image property list nested too deeply");
        final boolean empty = tag.endsWith("/");
        final String name = empty ? tag.substring(0, tag.length() - 1).trim() : tag;
        switch (name) {
            case "dict": {
                final Map<String, Object> m = new LinkedHashMap<String, Object>();
                if (empty) return m;
                while (true) {
                    final String t = nextTag();
                    if (t == null) throw new ArcanaCorruptedException("Disk image property list: unterminated <dict>");
                    if (t.equals("/dict")) return m;
                    if (!t.equals("key")) throw new ArcanaCorruptedException("Disk image property list: <key> expected in <dict>");
                    final String key = text("key");
                    final String vt = nextTag();
                    if (vt == null) throw new ArcanaCorruptedException("Disk image property list: value expected");
                    m.put(key, value(vt, depth + 1));
                }
            }
            case "array": {
                final List<Object> l = new ArrayList<Object>();
                if (empty) return l;
                while (true) {
                    final String t = nextTag();
                    if (t == null) throw new ArcanaCorruptedException("Disk image property list: unterminated <array>");
                    if (t.equals("/array")) return l;
                    l.add(value(t, depth + 1));
                }
            }
            case "true":
            case "false":
                if (!empty) text(name);
                return Boolean.valueOf(name.equals("true"));
            case "data": {
                if (empty) return new byte[0];
                return Base64.getMimeDecoder().decode(text("data"));
            }
            case "string":
            case "integer":
            case "real":
            case "date":
                return empty ? "" : text(name);
            default:
                throw new ArcanaCorruptedException("Disk image property list: unexpected <" + name + ">");
        }
    }

    /** Text up to the closing tag, entities decoded. */
    private String text(final String name) throws ArcanaCorruptedException {
        final String close = "</" + name + ">";
        final int e = s.indexOf(close, pos);
        if (e < 0) throw new ArcanaCorruptedException("Disk image property list: unterminated <" + name + ">");
        final String raw = s.substring(pos, e);
        pos = e + close.length();
        return raw.indexOf('&') < 0 ? raw : unescape(raw);
    }

    private static String unescape(final String t) {
        final StringBuilder sb = new StringBuilder(t.length());
        int i = 0;
        while (i < t.length()) {
            final char c = t.charAt(i);
            final int semi = c == '&' ? t.indexOf(';', i) : -1;
            if (semi < 0 || semi - i > 10) {
                sb.append(c);
                i++;
                continue;
            }
            final String ent = t.substring(i + 1, semi);
            String rep = null;
            if (ent.equals("lt")) rep = "<";
            else if (ent.equals("gt")) rep = ">";
            else if (ent.equals("amp")) rep = "&";
            else if (ent.equals("quot")) rep = "\"";
            else if (ent.equals("apos")) rep = "'";
            else if (ent.startsWith("#")) {
                try {
                    final int cp = ent.startsWith("#x") || ent.startsWith("#X") ? Integer.parseInt(ent.substring(2), 16) : Integer.parseInt(ent.substring(1));
                    if (Character.isValidCodePoint(cp)) rep = new String(Character.toChars(cp));
                } catch (final NumberFormatException ignored) {
                    // kept as text
                }
            }
            if (rep == null) {
                sb.append(c);
                i++;
            } else {
                sb.append(rep);
                i = semi + 1;
            }
        }
        return sb.toString();
    }
}
