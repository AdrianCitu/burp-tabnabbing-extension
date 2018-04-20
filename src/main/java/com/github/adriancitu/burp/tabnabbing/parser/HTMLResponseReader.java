package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
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
     * @return an {@link Optional} representing a {@link TabNabbingProblem}. The
     * optional is computed by calling for each byte
     * on each {@link IByteReaderObserver} attached
     * {@link IByteReaderObserver#problemFound()} and eventually
     * {@link IByteReaderObserver#getProblem()}.
     * <p>
     * The method returns after first problem found.
     */
    public Optional<TabNabbingProblem> getProblem() {
        for (index = 0; index < bytes.length; index++) {
            for (final IByteReaderObserver listener : observers) {
                listener.handleByte(this, bytes[index]);

                if (listener.problemFound()) {
                    return listener.getProblem();
                }
            }
        }

        return Optional.empty();
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
