package com.github.adriancitu.burp.tabnabbing.scanner;

import burp.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ScannerCheck Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Apr 19, 2018</pre>
 */
public class ScannerCheckTest {

    private IHttpRequestResponse iHttpRequestResponse =
            mock(IHttpRequestResponse.class);

    private IExtensionHelpers helpers = mock(IExtensionHelpers.class);

    private ScannerCheck scannerCheck = new ScannerCheck(helpers);
    private IResponseInfo iResponseInfo = mock(IResponseInfo.class);
    private IRequestInfo iRequestInfo = mock(IRequestInfo.class);

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: doPassiveScan(final IHttpRequestResponse iHttpRequestResponse)
     */
    @Test
    public void testDoPassiveScanHtmlProblemNoHeader() throws Exception {

        final Path path = Paths.get("src/test/resources/badHREFResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Collections.emptyList());

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(1, iScanIssues.size());
        assertEquals(
                IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(0).getIssueName());
        assertEquals(
                new URL("http://fake.com"),
                iScanIssues.get(0).getUrl());
    }

    @Test
    public void testDoPassiveScanHtmlProblemWithHeader() throws Exception {

        final Path path = Paths.get("src/test/resources/badHREFResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(1, iScanIssues.size());
        assertEquals(
                IssueType.HTML_LINK_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(0).getIssueName());
        assertEquals(
                new URL("http://fake.com"),
                iScanIssues.get(0).getUrl());
    }

    @Test
    public void testDoPassiveScanJSProblemNoHeader() throws Exception {

        final Path path = Paths.get("src/test/resources/badJSResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Collections.emptyList());

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(1, iScanIssues.size());
        assertEquals(
                IssueType.JAVASCRIPT_WIN_OPEN_NO_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(0).getIssueName());
        assertEquals(
                new URL("http://fake.com"),
                iScanIssues.get(0).getUrl());
    }

    @Test
    public void testDoPassiveScanJSProblemWithHeader() throws Exception {

        final Path path = Paths.get("src/test/resources/badJSResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(1, iScanIssues.size());
        assertEquals(
                IssueType.JAVASCRIPT_WIN_OPEN_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(0).getIssueName());
        assertEquals(
                new URL("http://fake.com"),
                iScanIssues.get(0).getUrl());
    }

} 
