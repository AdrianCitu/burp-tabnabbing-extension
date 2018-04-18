package com.github.adriancitu.burp.tabnabbing.util;

import java.util.List;
import java.util.Optional;
import java.util.Vector;

@SuppressWarnings("SpellCheckingInspection")
/**
 *
 */
public class HtmlByteArrayUtility {

    private HtmlByteArrayUtility() {

    }

    /**
     * Find first Tab Nabbing problem (an HTML a href or a JavaScript windows.open).
     *
     * @param source the HTML code as byte[]
     * @return java.util.Optional containing the first HTML chunk containing
     * a Tab Nabbing problem or Optional.empty otherwise.
     */
    public static Optional<byte[]> getFirstTabNabbingProblem(
            final byte[] source) {

        final List<Byte> buffer = new Vector<>();

        boolean foundLeftArrow = false;
        boolean foundStartOfJSWindowsOpen = false;
        boolean foundScriptTag = false;
        boolean foundStartOfHtmlHref = false;
        for (int i = 0; i < source.length; i++) {
            final byte actualByte = source[i];

            if (actualByte == 60d //<
                    && !foundLeftArrow) {
                foundLeftArrow = true;
                continue;
            }
            if (foundLeftArrow
                    && !foundStartOfJSWindowsOpen
                    && foundScriptTag(source, i)) {
                foundScriptTag = true;
                continue;
            }
            if (foundLeftArrow && foundHref(source, i)) {
                foundStartOfHtmlHref = true;
                buffer.add(source[i - 1]); //add < in the buffer
                buffer.add(source[i]); //add a in the buffer
                continue;
            }

            if (foundScriptTag && foundWindowsOpen(source, i)) {
                foundStartOfJSWindowsOpen = true;
                buffer.add(source[i]);
                continue;
            }

            if (foundStartOfHtmlHref || foundStartOfJSWindowsOpen) {
                buffer.add(source[i]);
            }

            if ((
                    foundStartOfHtmlHref
                            && source[i] == 62d //>
            ) || (
                    foundStartOfJSWindowsOpen
                            && source[i] == 59d //;
            )) {

                if (tabNabbingProblemFound(fromByteListToByteArray(buffer))) {
                    return Optional.of(fromByteListToByteArray(buffer));
                } else {
                    buffer.clear();
                    foundLeftArrow = false;
                    if (foundStartOfHtmlHref) {
                        foundStartOfHtmlHref = false;
                    }

                    if (foundStartOfJSWindowsOpen) {
                        foundScriptTag = false;
                        foundStartOfJSWindowsOpen = false;
                    }

                }

            }

        }

        return Optional.empty();
    }

    public static byte[] fromByteListToByteArray(final List<Byte> byteList) {
        final byte[] returnValue = new byte[byteList.size()];

        for (int i = 0; i < byteList.size(); i++) {
            returnValue[i] = byteList.get(i);
        }

        return returnValue;
    }

    /**
     * Receive as parameter a {@link Byte} array representing
     * a href HTML tag or a windows.open JavaScript function.
     * <p>
     * The mmethod checks that the HTML tag or the JavaScript function
     * call have the good parameters to not be vulnerable to
     * tab nabbing problem meaning the HTML href have a
     * rel="noreferrer noopener" attribute and
     * the JavaScript function call have the "noreferrer,noopener"
     * parameters.
     * <p>
     * This method is package protected only for testing purposes.
     *
     * @param buffer a list of {@link Byte}.
     * @return true if the buffer (that contains a HTML href
     * or a JavaScript windows.open call) is vulnerable
     * to tab napping problem or false otherwise.
     */
    public static boolean tabNabbingProblemFound(final byte[] buffer) {
        final String string = new String(buffer)
                .toLowerCase()
                .replaceAll(" ", "")
                .replaceAll("'", "\"");

        if (string.startsWith("<ahref")
                && !string.contains("rel=\"noopener\"")
                && !string.contains("rel=\"noreferrernoopener\"")
                && !string.contains("rel=\"noopenernoreferrer\"")) {
            return true;
        }

        return string.startsWith("window.open")
                && !string.contains("noopener")
                && !string.contains("noreferrer,noopener")
                && !string.contains("noopener,noreferrer");
    }

    /**
     * Check that as of offset start_offset the source contains the
     * JavaScript windows.open.
     * <p>
     * This is package protected only for testing purposes.
     *
     * @param source       byte[] representing JavaScript.
     * @param start_offset the offset from witch shouls start the search
     * @return true if the source starts with the "windows.open" code
     * from start_offset, false otherwise.
     */
    static boolean foundWindowsOpen(
            final byte[] source, final int start_offset) {
        return
                (source[start_offset] == 119d //w
                        || source[start_offset] == 87d //W
                )
                        && (source[start_offset + 1] == 105d //i
                        || source[start_offset + 1] == 73d //I
                )
                        && (source[start_offset + 2] == 110d //n
                        || source[start_offset + 2] == 78d //N
                )
                        && (source[start_offset + 3] == 100d //d
                        || source[start_offset + 3] == 68d //D
                )
                        && (source[start_offset + 4] == 111d //o
                        || source[start_offset + 4] == 79d //O
                )
                        && (source[start_offset + 5] == 119d //w
                        || source[start_offset + 5] == 87d //W
                )
                        && source[start_offset + 6] == 46d //.
                        && (source[start_offset + 7] == 111d //o
                        || source[start_offset + 7] == 79d //O
                )
                        && (source[start_offset + 8] == 112d //p
                        || source[start_offset + 8] == 80d //P
                )
                        && (source[start_offset + 9] == 101d //e
                        || source[start_offset + 9] == 69d //E
                )
                        && (source[start_offset + 10] == 110d //n
                        || source[start_offset + 10] == 78d //N

                );
    }

    /**
     * Check that as of offset start_offset the source contains the
     * HTML "a href".
     * <p>
     * This is package protected only for testing purposes.
     *
     * @param source       byte[] representing HTML.
     * @param start_offset the offset from witch shouls start the search
     * @return true if the source starts with the "a href" code
     * from start_offset, false otherwise.
     */
    static boolean foundHref(final byte[] source, final int start_offset) {
        return (source[start_offset] == 97d //a
                || source[start_offset] == 65d //A
        )
                && (source[start_offset + 1] == 32d //space
                || source[start_offset + 1] == 9d //tab
        )
                && (source[start_offset + 2] == 104d //h
                || source[start_offset + 2] == 72d //H
        )
                && (source[start_offset + 3] == 114d //r
                || source[start_offset + 3] == 82d //R
        )
                && (source[start_offset + 4] == 101d //e
                || source[start_offset + 4] == 69 //E
        )
                && (source[start_offset + 5] == 102d //f
                || source[start_offset + 5] == 70d //F
        );
    }

    /**
     * Check that as of offset start_offset the source contains the
     * JavaSCript "script>".
     * <p>
     * This is package protected only for testing purposes.
     *
     * @param source       byte[] representing HTML.
     * @param start_offset the offset from witch shouls start the search
     * @return true if the source starts with the "script>" tag
     * from start_offset, false otherwise.
     */
    static boolean foundScriptTag(
            final byte[] source, final int start_offset) {
        return
                (source[start_offset] == 115d //s
                        || source[start_offset] == 83d //S
                )
                        && (source[start_offset + 1] == 99d  //c
                        || source[start_offset + 1] == 67d //C
                )
                        && (source[start_offset + 2] == 114d //r
                        || source[start_offset + 2] == 82D //R
                )
                        && (source[start_offset + 3] == 105d //i
                        || source[start_offset + 3] == 73d //I
                )
                        && (source[start_offset + 4] == 112d //p
                        || source[start_offset + 4] == 80d //P
                )
                        && (source[start_offset + 5] == 116d //t
                        || source[start_offset + 5] == 84d //T
                )
                        && source[start_offset + 6] == 62d //>
                ;
    }

}
