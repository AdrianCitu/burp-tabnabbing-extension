package com.github.adriancitu.burp.tabnabbing.parser;

final public class TabNabbingProblem {

    private final String problem;
    private final ProblemType type;

    TabNabbingProblem(ProblemType type, String problem) {
        this.type = type;
        this.problem = problem;
    }

    public enum ProblemType {
        HTML, JAVA_SCRIPT
    }

    public String getProblem() {
        return this.problem;
    }

    public ProblemType getProblemType() {
        return this.type;
    }
}
