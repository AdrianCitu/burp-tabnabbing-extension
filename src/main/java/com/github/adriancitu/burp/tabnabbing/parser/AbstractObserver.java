package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;

import java.util.ArrayList;
import java.util.List;

public abstract class AbstractObserver implements IByteReaderObserver {

    private final List<Byte> buffer = new ArrayList<>();
    private boolean problemFound = false;

    List<Byte> getBuffer() {
        return buffer;
    }

    void setProblemFound(boolean problemFound) {
        this.problemFound = problemFound;
    }

    @Override
    public boolean problemFound() {
        return problemFound;
    }

    String getProblemAsString() {
        return new String(HtmlByteArrayUtility.fromByteListToByteArray(buffer));
    }

    @Override
    public void close() {
        this.buffer.clear();
        this.problemFound = false;
    }
}
