package com.github.adriancitu.burp.tabnabbing.scanner;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;
import java.util.Arrays;
import java.util.Objects;

class CustomScanIssue implements IScanIssue {

    private final IssueType issueType;
    private final String issueDetail;
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;

    public CustomScanIssue(
            final IHttpRequestResponse iHttpRequestResponse,
            final URL url,
            final IssueType issueType,
            final String issueDetail) {

        this.httpService = iHttpRequestResponse.getHttpService();
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[]{iHttpRequestResponse};
        this.issueType = issueType;
        this.issueDetail = issueDetail.replaceAll("<", "&lt;").trim();
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return this.issueType.getName();
    }

    @Override
    public int getIssueType() {
        return this.issueType.getName().hashCode();
    }

    @Override
    public String getSeverity() {
        return this.issueType.getSeverity();
    }

    @Override
    public String getConfidence() {
        return this.issueType.getConfidence();
    }

    @Override
    public String getIssueBackground() {
        return this.issueType.getIssueBackground();
    }

    @Override
    public String getRemediationBackground() {

        return this.issueType.getRemediationDetail();
    }

    @Override
    public String getIssueDetail() {
        return this.issueDetail;
    }

    @Override
    public String getRemediationDetail() {
        return this.issueType.getRemediationDetail();
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CustomScanIssue)) return false;
        CustomScanIssue that = (CustomScanIssue) o;
        return getIssueType() == that.getIssueType() &&
                Objects.equals(getIssueDetail(), that.getIssueDetail()) &&
                Objects.equals(getHttpService(), that.getHttpService()) &&
                Objects.equals(getUrl(), that.getUrl()) &&
                Arrays.equals(getHttpMessages(), that.getHttpMessages());
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(getIssueType(), getIssueDetail(), getHttpService(), getUrl());
        result = 31 * result + Arrays.hashCode(getHttpMessages());
        return result;
    }

    @Override
    public String toString() {
        return "CustomScanIssue{" +
                "issueType=" + issueType +
                ", issueDetail='" + issueDetail + '\'' +
                ", httpService=" + httpService +
                ", url=" + url +
                ", httpMessages=" + Arrays.toString(httpMessages) +
                '}';
    }
}
