package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.IssueType;

import java.util.Objects;

public final class TabNabbingProblem {

    private final String problem;
    private final IssueType type;

    TabNabbingProblem(IssueType type, String problem) {
        this.type = type;
        this.problem = problem;
    }

    public String getProblem() {
        return this.problem;
    }

    public IssueType getIssueType() {
        return this.type;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TabNabbingProblem)) return false;
        TabNabbingProblem that = (TabNabbingProblem) o;
        return Objects.equals(getProblem(), that.getProblem()) &&
                type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getProblem(), type);
    }
}
