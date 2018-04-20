package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.Closeable;
import java.util.List;

/**
 * Interface representing the observable/subject from the observer pattern.
 * The implementations of this interface will have attach observers (a list of
 * {@link IByteReaderObserver}) and it will have to feed the observers
 * with the bytes, byte by byte by calling the
 * {@link IByteReaderObserver#handleByte(IByteReader, byte)}.
 * <p>
 * In some cases the {@link IByteReaderObserver} will ask for more bytes from
 * the observable by calling {@link IByteReader#fetchMoreBytes(int)}.
 */
public interface IByteReader extends Closeable {

    /**
     * Called by the observers if wanted more bytes to parse.
     *
     * @param howManyBytes how many more bytes the {@link IByteReader} should
     *                     return.
     * @return the number of bytes asked or all the remaining bytes if
     * the asked bytes are more that remaining ones.
     */
    public byte[] fetchMoreBytes(int howManyBytes);

    /**
     * @param observers the observers to attach to this observable/subject
     */
    public void attachObservers(List<IByteReaderObserver> observers);
}
