package com.github.adriancitu.burp.tabnabbing.parser;

public final class TabNabbingProblem {

    private final String problem;
    private final ProblemType type;

    TabNabbingProblem(ProblemType type, String problem) {
        this.type = type;
        this.problem = problem;
    }

    public String getProblem() {
        return this.problem;
    }

    public ProblemType getProblemType() {
        return this.type;
    }

    public enum ProblemType {
        HTML, JAVA_SCRIPT
    }
}
