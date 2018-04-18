package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.Closeable;
import java.util.List;

public interface IByteReader extends Closeable {

    public byte[] pull(int howManyBytes);

    public void attachObservers(List<IByteReaderObserver> listeners);
}
