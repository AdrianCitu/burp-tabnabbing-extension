package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;

import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JSWindowsOpenReaderObserver extends AbstractObserver {

    private static final Logger LOGGER =
            Logger.getLogger(JSWindowsOpenReaderObserver.class.getName());

    private boolean scriptTagFound = false;
    private boolean windowsOpenFound = false;

    @Override
    public void push(IByteReader byteReader, byte toHandle) {

        try {
            if (problemFound()) {
                return;
            }

            //<
            if (toHandle == 60d) {
                final byte[] next7Bytes = byteReader.pull(7);
                if ("script>".equalsIgnoreCase(new String(next7Bytes))) {
                    scriptTagFound = true;
                    return;
                }

                if (scriptTagFound) {
                    final byte[] next8Bytes = byteReader.pull(8);
                    if ("/script>".equalsIgnoreCase(new String(next8Bytes))) {
                        scriptTagFound = false;
                        return;
                    }
                }
                return;
            }

            //w or W
            if (scriptTagFound
                    && (toHandle == 119d //w
                    || toHandle == 87d) //W
                    ) {
                final byte[] next11Bytes = byteReader.pull(10);
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

                return;
            }
        } catch (RuntimeException e) {
            this.close();
            LOGGER.log(Level.WARNING, e.getMessage(), e);
        }
    }

    @Override
    public Optional<TabNabbingProblem> getProblem() {

        if (problemFound()) {
            return Optional.of(
                    new TabNabbingProblem(
                            TabNabbingProblem.ProblemType.JAVA_SCRIPT,
                            getProblemAsString()));
        }
        return Optional.empty();
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
