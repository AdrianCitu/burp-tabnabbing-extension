package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

public class HTMLResponseReader implements IByteReader {

    private final byte[] bytes;
    private final int bytesLength;
    private List<IByteReaderObserver> observers;
    private int index = 0;

    public HTMLResponseReader(final byte[] bytes) {
        this.bytes = bytes;
        this.bytesLength = this.bytes.length;
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
        List<TabNabbingProblem> returnValue =
                new ArrayList<>(observers.size());


        for (index = 0; index < bytes.length; index++) {
            Iterator<IByteReaderObserver> iterator = observers.iterator();
            while (iterator.hasNext()) {
                IByteReaderObserver observer = iterator.next();
                observer.handleByte(this, bytes[index]);

                if (observer.problemFound()
                        && observer.getProblem().isPresent()) {
                    returnValue.add(observer.getProblem().get());
                    iterator.remove();
                }
            }
        }

        return returnValue;
    }

    private int computeTheSizeOfTheResponse(final int initialNumberOgAskedBytes) {

        final int askedOffset = index + initialNumberOgAskedBytes;

        if (askedOffset > bytesLength) {
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
