package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.IssueType;
import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;

import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Observer that is able to find HTML anchor tag and check if it is
 * vulnerable to the tabnabbing problem.
 */
public class HTMLAnchorReaderObserver extends AbstractObserver {

    private static final Logger LOGGER =
            Logger.getLogger(HTMLAnchorReaderObserver.class.getName());

    /**
     * true if the '<a' is found.
     */
    private boolean htmlAnchorFound = false;

    public HTMLAnchorReaderObserver(boolean noReffererHtmlHeader) {
        super(noReffererHtmlHeader);
    }

    @Override
    public void handleByte(final IByteReader byteReader, final byte toHandle) {

        try {
            if (problemFound()) {
                return;
            }

            //<
            if (toHandle == 60d) {
                final byte[] nextTwoBytes = byteReader.fetchMoreBytes(2);

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
                final byte[] nextBytes = byteReader.fetchMoreBytes(2);

                if ("a>".equalsIgnoreCase(new String(nextBytes))) {
                    this.close();
                }

                return;
            }

        } catch (final RuntimeException e) {
            this.close();
            LOGGER.log(Level.WARNING, e.getMessage(), e);
        }
    }

    @Override
    public Optional<TabNabbingProblem> getProblem() {
        if (problemFound() && isNoReferrerHeaderPresent()) {
            return Optional.of(
                    new TabNabbingProblem(
                            IssueType.HTML_LINK_REFERRER_POLICY_HEADER,
                            getProblemAsString()));
        }

        if (problemFound() && !isNoReferrerHeaderPresent()) {
            return Optional.of(
                    new TabNabbingProblem(
                            IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER,
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
