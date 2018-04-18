package com.github.adriancitu.burp.tabnabbing.scanner;

import burp.*;
import com.github.adriancitu.burp.tabnabbing.parser.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class ScannerCheck implements IScannerCheck {


    private final IExtensionHelpers helpers;

    public ScannerCheck(final IExtensionHelpers helpers) {

        this.helpers = helpers;
    }

    private HTMLResponseReader createResponseReader(byte[] httpToParse) {
        HTMLResponseReader httpReader = new HTMLResponseReader(httpToParse);

        List<IByteReaderObserver> observers = new ArrayList<>();
        observers.add(new HTMLAnchorReaderObserver());
        observers.add(new JSWindowsOpenReaderObserver());
        httpReader.attachObservers(observers);

        return httpReader;
    }

    @Override
    public List<IScanIssue> doPassiveScan(
            final IHttpRequestResponse iHttpRequestResponse) {

        byte[] htmlResponse = iHttpRequestResponse.getResponse();

        HTMLResponseReader httpReader = createResponseReader(htmlResponse);

        try {

            final Optional<TabNabbingProblem> problem = httpReader.getProblem();

            if (problem.isPresent()) {
                boolean noReferrerHeaderPresent =
                        helpers.analyzeResponse(htmlResponse)
                                .getHeaders()
                                .stream()
                                .anyMatch(header ->
                                        "referrer-policy:no-referrer"
                                                .equals(header.toLowerCase()
                                                        .replaceAll(" ", "")));
                if (noReferrerHeaderPresent) {
                    if (problem.get().getProblemType().equals(TabNabbingProblem.ProblemType.HTML)) {
                        Arrays.asList(new CustomScanIssue(
                                iHttpRequestResponse,
                                helpers.analyzeRequest(iHttpRequestResponse).getUrl(),
                                IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER,
                                problem.get().getProblem()

                        ));
                    }
                    if (problem.get().getProblemType().equals(TabNabbingProblem.ProblemType.JAVA_SCRIPT)) {
                        Arrays.asList(new CustomScanIssue(
                                iHttpRequestResponse,
                                helpers.analyzeRequest(iHttpRequestResponse).getUrl(),
                                IssueType.JAVASCRIPT_WIN_OPEN_NO_REFERRER_POLICY_HEADER,
                                problem.get().getProblem()

                        ));
                    }
                } else {
                    if (problem.get().getProblemType().equals(TabNabbingProblem.ProblemType.HTML)) {
                        Arrays.asList(new CustomScanIssue(
                                iHttpRequestResponse,
                                helpers.analyzeRequest(iHttpRequestResponse).getUrl(),
                                IssueType.HTML_LINK_REFERRER_POLICY_HEADER,
                                problem.get().getProblem()

                        ));
                    }
                    if (problem.get().getProblemType().equals(TabNabbingProblem.ProblemType.JAVA_SCRIPT)) {
                        Arrays.asList(new CustomScanIssue(
                                iHttpRequestResponse,
                                helpers.analyzeRequest(iHttpRequestResponse).getUrl(),
                                IssueType.JAVASCRIPT_WIN_OPEN_REFERRER_POLICY_HEADER,
                                problem.get().getProblem()

                        ));
                    }
                }
            }
        } finally {
            try {
                httpReader.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(
            final IHttpRequestResponse iHttpRequestResponse,
            final IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(
            final IScanIssue existingIssue,
            final IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}
