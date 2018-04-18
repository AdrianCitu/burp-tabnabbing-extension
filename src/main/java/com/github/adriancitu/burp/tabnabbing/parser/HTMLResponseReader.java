package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Vector;

public class HTMLResponseReader implements IByteReader {

    private final byte[] bytes;
    private final int bytesLength;
    private List<IByteReaderObserver> listeners;
    private int index = 0;

    public HTMLResponseReader(final byte[] bytes) {
        this.bytes = bytes;
        this.bytesLength = this.bytes.length;
    }

    public Optional<TabNabbingProblem> getProblem() {
        for (index = 0; index < bytes.length; index++) {
            for (final IByteReaderObserver listener : listeners) {
                listener.push(this, bytes[index]);

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
            return bytesLength - index -1;
        }

        return initialNumberOgAskedBytes;
    }

    @Override
    public byte[] pull(final int howManyBytes) {
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
        listeners = new Vector<>(readerList.size());
        for (final IByteReaderObserver listener : readerList) {
            listeners.add(listener);
        }
    }

    @Override
    public void close() throws IOException {
        for (final IByteReaderObserver listener : this.listeners) {
            listener.close();
        }
        listeners.clear();
        index = 0;
    }
}
