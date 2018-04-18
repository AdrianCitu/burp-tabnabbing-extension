package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;

import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

/**
 *
 */
public class HTMLAnchorReaderObserver extends AbstractObserver {

    private final static Logger LOGGER =
            Logger.getLogger(HTMLAnchorReaderObserver.class.getName());

    private boolean htmlAnchorFound = false;

    @Override
    public void push(final IByteReader byteReader, final byte toHandle) {

        try {
            if (problemFound()) {
                return;
            }

            //<
            if (toHandle == 60d) {
                final byte[] nextTwoBytes = byteReader.pull(2);

                if (nextTwoBytes != null
                        && nextTwoBytes.length == 2 &&
                        //a or A
                        (nextTwoBytes[0] == 97d || nextTwoBytes[0] == 65d)
                        //space or tab
                        && (nextTwoBytes[1] == 32d || nextTwoBytes[1] == 9d)) {

                    htmlAnchorFound = true;
                    getBuffer().add(toHandle);

                    return;
                }
            }
            if (htmlAnchorFound) {
                getBuffer().add(toHandle);
                //>
                if (toHandle == 62d) {
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

            // /
            if (toHandle == 47d) {
                //look for a>
                final byte[] nextBytes = byteReader.pull(2);

                if ("a>".equals(new String(nextBytes).toLowerCase())) {
                    this.close();
                }

                return;
            }

        } catch (final Throwable e) {
            this.close();
            LOGGER.warning(
                    "Exception thrown by the TabNabbing extension:"
                            + e.getMessage());
        }
    }

    @Override
    public Optional<TabNabbingProblem> getProblem() {
        if (problemFound()) {
           return Optional.of(
                    new TabNabbingProblem(
                            TabNabbingProblem.ProblemType.HTML,
                            getProblemAsString()));
        }

        return Optional.empty();
    }


    @Override
    public void close() {
        super.close();
        this.htmlAnchorFound = false;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HTMLAnchorReaderObserver)) return false;
        HTMLAnchorReaderObserver that = (HTMLAnchorReaderObserver) o;
        return htmlAnchorFound == that.htmlAnchorFound;
    }

    @Override
    public int hashCode() {
        return Objects.hash(htmlAnchorFound);
    }


}
