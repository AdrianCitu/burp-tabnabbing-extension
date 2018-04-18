package com.github.adriancitu.burp.tabnabbing.parser;

import java.io.Closeable;
import java.util.Optional;

public interface IByteReaderObserver extends Closeable {

    void push(IByteReader reader, byte toHandle);

    boolean problemFound();

    Optional<TabNabbingProblem> getProblem();
}
