package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.IssueType;

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
}
