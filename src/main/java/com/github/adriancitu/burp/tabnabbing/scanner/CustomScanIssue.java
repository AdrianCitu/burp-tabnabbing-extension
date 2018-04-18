package com.github.adriancitu.burp.tabnabbing.scanner;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private final IssueType issueType;
    private final String issueDetail;

    public CustomScanIssue(
            final IHttpRequestResponse iHttpRequestResponse,
            final URL url,
            final IssueType issueType,
            final String issueDetail) {

        this.httpService = iHttpRequestResponse.getHttpService();
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[]{iHttpRequestResponse};
        this.issueType = issueType;
        this.issueDetail = issueDetail;
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
        return 0;
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

}
