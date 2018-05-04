package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.ScanStrategy;

import java.io.IOException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HTMLResponseReader implements IByteReader {

    /**
     * System property to drive the scanning strategy.
     */
    public static final String SCAN_STRATEGY_SYSTEM_PROPERTY
            = "tabnabbing.pagescan.strategy";
    private static final Logger LOGGER =
            Logger.getLogger(HTMLResponseReader.class.getName());
    private final byte[] bytes;
    private final int bytesLength;
    private List<IByteReaderObserver> observers;
    private int index = 0;
    private ScanStrategy scanStrategy = ScanStrategy.STOP_AFTER_FIRST_FINDING;


    public HTMLResponseReader(final byte[] bytes) {
        this.bytes = bytes;
        this.bytesLength = this.bytes.length;

        try {
            scanStrategy = ScanStrategy.valueOf(System.getProperty(
                    SCAN_STRATEGY_SYSTEM_PROPERTY,
                    ScanStrategy.SCAN_ENTIRE_PAGE.toString()));
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Cannot compute scan strategy", e);
        }

    }

    /**
     * @return a {@link List} of {@link TabNabbingProblem}s. The
     * list is computed by calling for each byte
     * on each {@link IByteReaderObserver} attached
     * {@link IByteReaderObserver#problemFound()} and eventually
     * {@link IByteReaderObserver#getProblem()}.
     * <p>
     * Once an observer found a problem, then it is removed from the
     * list of observer so the method will return at most one problem
     * by listener.
     */
    public List<TabNabbingProblem> getProblems() {
        Set<TabNabbingProblem> setOfProblems =
                new HashSet<>(observers.size());


        for (index = 0; index < bytes.length; index++) {
            Iterator<IByteReaderObserver> iterator = observers.iterator();
            while (iterator.hasNext()) {
                IByteReaderObserver observer = iterator.next();
                observer.handleByte(this, bytes[index]);

                if (observer.problemFound()
                        && observer.getProblem().isPresent()) {
                    setOfProblems.add(observer.getProblem().get());
                    try {
                        switch (scanStrategy) {
                            case STOP_AFTER_FIRST_FINDING:
                                this.close();
                                return new ArrayList<>(setOfProblems);
                            case STOP_AFTER_FIRST_HTML_AND_JS_FINDING:
                                observer.close();
                                iterator.remove();
                                break;
                            case SCAN_ENTIRE_PAGE:
                                for (final IByteReaderObserver listener : this.observers) {
                                    listener.close();
                                }
                                break;

                            default:
                                break;
                        }
                    } catch (IOException e) {
                        LOGGER.log(Level.INFO, e.getMessage(), e);
                    }
                }
            }
        }

        return new ArrayList<>(setOfProblems);
    }

    private int computeTheSizeOfTheResponse(final int initialNumberOgAskedBytes) {

        final int askedOffset = index + initialNumberOgAskedBytes;

        if (askedOffset >= bytesLength) {
            return bytesLength - index - 1;
        }

        return initialNumberOgAskedBytes;
    }

    @Override
    public byte[] fetchMoreBytes(final int howManyBytes) {
        final byte[] returnValue =
                new byte[computeTheSizeOfTheResponse(howManyBytes)];

        int returnValueIndex = 0;
        for (int i = index + 1; i <= index + returnValue.length; i++) {
            returnValue[returnValueIndex] = bytes[i];
            returnValueIndex++;
        }
        return returnValue;
    }

    @Override
    public void attachObservers(
            final List<IByteReaderObserver> readerList) {
        observers = new Vector<>(readerList.size());
        for (final IByteReaderObserver listener : readerList) {
            observers.add(listener);
        }
    }

    @Override
    public void close() throws IOException {
        for (final IByteReaderObserver listener : this.observers) {
            listener.close();
        }
        observers.clear();
        index = 0;
    }
}
