package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.IssueType;
import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;

import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Observer that is able to find JavaScript "<script>" tag and
 * "window.open" call inside a code block.
 */
public class JSWindowsOpenReaderObserver extends AbstractObserver {

    private static final Logger LOGGER =
            Logger.getLogger(JSWindowsOpenReaderObserver.class.getName());

    private boolean scriptTagFound = false;
    private boolean windowsOpenFound = false;

    public JSWindowsOpenReaderObserver(boolean noReferrerHeaderPresent1) {
        super(noReferrerHeaderPresent1);
    }


    @Override
    public void handleByte(IByteReader byteReader, byte toHandle) {

        try {
            if (problemFound()) {
                return;
            }

            //<
            handle60dByte(byteReader, toHandle);

            //w or W
            if (scriptTagFound
                    && (toHandle == 119d //w
                    || toHandle == 87d) //W
                    ) {
                final byte[] next11Bytes = byteReader.fetchMoreBytes(10);
                if ("indow.open".equalsIgnoreCase(new String(next11Bytes))) {
                    windowsOpenFound = true;
                    getBuffer().add(toHandle);
                    return;
                }
            }

            if (windowsOpenFound) {
                getBuffer().add(toHandle);

                //;
                if (toHandle == 59d) {
                    if (HtmlByteArrayUtility
                            .tabNabbingProblemFound(
                                    HtmlByteArrayUtility
                                            .fromByteListToByteArray(getBuffer())
                            )) {
                        setProblemFound(true);
                    } else {
                        this.close();
                    }
                }
            }
        } catch (RuntimeException e) {
            this.close();
            LOGGER.log(Level.WARNING, e.getMessage(), e);
        }
    }

    private void handle60dByte(IByteReader byteReader, byte toHandle) {
        if (toHandle == 60d) {
            final byte[] next7Bytes = byteReader.fetchMoreBytes(7);
            if ("script>".equalsIgnoreCase(new String(next7Bytes))) {
                scriptTagFound = true;
                return;
            }

            if (scriptTagFound) {
                final byte[] next8Bytes = byteReader.fetchMoreBytes(8);
                if ("/script>".equalsIgnoreCase(new String(next8Bytes))) {
                    scriptTagFound = false;
                }
            }
        }
    }

    @Override
    public Optional<TabNabbingProblem> getProblem() {

        if (problemFound()) {
            return Optional.of(
                    new TabNabbingProblem(
                            isNoReferrerHeaderPresent() ?
                                    IssueType.JAVASCRIPT_WIN_OPEN_REFERRER_POLICY_HEADER :
                                    IssueType.JAVASCRIPT_WIN_OPEN_NO_REFERRER_POLICY_HEADER
                            ,
                            getProblemAsString()));
        } else {
            return Optional.empty();
        }
    }


    @Override
    public void close() {
        super.close();
        this.windowsOpenFound = false;
        this.scriptTagFound = false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof JSWindowsOpenReaderObserver)) return false;
        JSWindowsOpenReaderObserver that = (JSWindowsOpenReaderObserver) o;
        return scriptTagFound == that.scriptTagFound &&
                windowsOpenFound == that.windowsOpenFound;
    }

    @Override
    public int hashCode() {
        return Objects.hash(scriptTagFound, windowsOpenFound);
    }
}
