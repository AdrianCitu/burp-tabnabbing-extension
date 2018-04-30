package com.github.adriancitu.burp.tabnabbing.scanner;

/**
 * Enum representing the possible types of tabnabbing issues; javascript
 * or html side, with or with no Referrer-Policy: no-referrer HTTP header.
 */
public enum IssueType {

    HTML_LINK_NO_REFERRER_POLICY_HEADER(
            "Tabnabbing (HTML link and no referrer header)",
            "Found HTML link with no referrer attribute" +
                    " and no Referrer-Policy header present",
            Constants.SEVERITY_INFO,
            Constants.CONFIDENCE_CERTAIN,
            Constants.HTML_REMEDIATION
                    + " and "
                    + Constants.HEADER_REMEDIATION
    ),
    HTML_LINK_REFERRER_POLICY_HEADER(
            "Tabnabbing(HTML link and referrer header)",
            "Found HTML link with no referrer attribute " +
                    "BUT Referrer-Policy header present",
            Constants.SEVERITY_INFO,
            Constants.CONFIDENCE_CERTAIN,
            Constants.HTML_REMEDIATION
    ),

    JAVASCRIPT_WIN_OPEN_NO_REFERRER_POLICY_HEADER(
            "Tabnabbing(Javascript window open and no referrer header)",
            " Found Javascript call to window.open" +
                    " and no Referrer-Policy header present",
            Constants.SEVERITY_INFO,
            Constants.CONFIDENCE_CERTAIN,
            Constants.JS_REMEDIATION
                    + " and "
                    + Constants.HEADER_REMEDIATION
    ),
    JAVASCRIPT_WIN_OPEN_REFERRER_POLICY_HEADER(
            "Tabnabbing(Javascript window open and referrer header)",
            " Found Javascript call to window.open " +
                    " BUT Referrer-Policy header present",
            Constants.SEVERITY_INFO,
            Constants.CONFIDENCE_CERTAIN,
            Constants.JS_REMEDIATION
    );

    private final String name;
    private final String issueBackground;
    private final String severity;
    private final String confidence;
    private final String remediationDetail;

    IssueType(
            final String issueName,
            final String issueBackground,
            final String issueSeverity,
            final String issueConfidence,
            final String remediationDetail) {

        this.name = issueName;
        this.issueBackground = issueBackground;
        this.severity = issueSeverity;
        this.confidence = issueConfidence;
        this.remediationDetail = remediationDetail;
    }

    public String getConfidence() {
        return confidence;
    }

    public String getName() {
        return name;
    }

    public String getIssueBackground() {
        return issueBackground;
    }

    public String getSeverity() {
        return severity;
    }

    public String getRemediationDetail() {
        return remediationDetail;
    }

    private static class Constants {
        public static final String JS_REMEDIATION = "Open the popup and set the opener and referrer policy instruction " +
                "(ex: var newWindow = window.open(url, name, 'noopener,noreferrer');) " +
                "and reset the opener link (ex:newWindow.opener = null;)";
        public static final String HTML_REMEDIATION = "For html link, add the attribute rel=\"noopener noreferrer\" for every links.";
        public static final String HEADER_REMEDIATION = "add the HTTP response header Referrer-Policy: no-referrer the every HTTP " +
                "responses send by the application";
        public static final String SEVERITY_INFO = "Information";
        public static final String CONFIDENCE_CERTAIN = "Certain";
    }
}
