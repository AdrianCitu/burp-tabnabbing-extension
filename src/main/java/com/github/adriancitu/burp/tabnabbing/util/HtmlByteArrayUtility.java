package com.github.adriancitu.burp.tabnabbing.util;

import java.util.List;

@SuppressWarnings("SpellCheckingInspection")
/**
 *
 */
public class HtmlByteArrayUtility {

    private HtmlByteArrayUtility() {

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

}
