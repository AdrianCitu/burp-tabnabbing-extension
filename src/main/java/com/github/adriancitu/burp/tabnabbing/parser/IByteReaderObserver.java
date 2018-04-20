package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.Closeable;
import java.util.Optional;

/**
 * Interface representing an observer for the {@link IByteReader}
 * (which represents the observable/subject from the observer pattern).
 */
public interface IByteReaderObserver extends Closeable {

    /**
     * @param reader   the subject on which this observer is attached
     * @param toHandle the byte that the observer will have to handle.
     */
    void handleByte(IByteReader reader, byte toHandle);

    /**
     * @return true if a problem was found, false otherwise
     */
    boolean problemFound();

    /**
     * @return the problem found as instance of {@link TabNabbingProblem}
     * or an empty optional otherwise.
     */
    Optional<TabNabbingProblem> getProblem();
}
