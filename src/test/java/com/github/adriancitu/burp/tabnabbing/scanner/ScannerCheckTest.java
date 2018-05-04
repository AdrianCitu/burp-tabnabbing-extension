package com.github.adriancitu.burp.tabnabbing.scanner;

import burp.*;
import com.github.adriancitu.burp.tabnabbing.parser.HTMLResponseReader;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ScannerCheck Tester.
 */
public class ScannerCheckTest {

    private IHttpRequestResponse iHttpRequestResponse =
            mock(IHttpRequestResponse.class);

    private IExtensionHelpers helpers = mock(IExtensionHelpers.class);

    private ScannerCheck scannerCheck = new ScannerCheck(helpers);
    private IResponseInfo iResponseInfo = mock(IResponseInfo.class);
    private IRequestInfo iRequestInfo = mock(IRequestInfo.class);

    private static <T> boolean containsUniqueValues(List<T> list) {
        return list.stream().allMatch(new HashSet<>()::add);
    }

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

    @Test
    public void testDoPassiveScanHTMLProblemAndJsProblem() throws Exception {

        System.setProperty(HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.STOP_AFTER_FIRST_HTML_AND_JS_FINDING.toString());
        final Path path = Paths.get("src/test/resources/badHrefResponseAndBadJsResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(2, iScanIssues.size());

        assertEquals(
                IssueType.HTML_LINK_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(0).getIssueName());


        assertEquals(
                IssueType.JAVASCRIPT_WIN_OPEN_REFERRER_POLICY_HEADER.getName(),
                iScanIssues.get(1).getIssueName());

        assertEquals(
                new URL("http://fake.com"),
                iScanIssues.get(0).getUrl());

        System.setProperty(HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.STOP_AFTER_FIRST_FINDING.toString());

    }

    @Test
    public void testDoPassiveScanNoProblem() throws Exception {
        final Path path = Paths.get("src/test/resources/bigGoodHREFResponse.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(0, iScanIssues.size());
    }

    @Test(timeout = 250)
    public void testDoPassiveScanTimeoutCheck() throws Exception {
        final Path path = Paths.get("src/test/resources/bigHTMLFileWithNoHref.html");
        final byte[] data = Files.readAllBytes(path);

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertEquals(0, iScanIssues.size());
    }

    @Test
    public void testIssueWithSameUrlPresent() throws Exception {
        final Path path = Paths.get("src/test/resources/realFileFromSlate.html");
        final byte[] data = Files.readAllBytes(path);

        System.setProperty(HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.SCAN_ENTIRE_PAGE.toString());

        when(iHttpRequestResponse.getResponse()).thenReturn(data);

        when(helpers.analyzeResponse(any())).thenReturn(iResponseInfo);
        when(iResponseInfo.getHeaders()).thenReturn(Arrays.asList("referrer-policy:no-referrer"));

        when(helpers.analyzeRequest(any(IHttpRequestResponse.class))).thenReturn(iRequestInfo);
        when(iRequestInfo.getUrl()).thenReturn(new URL("http://fake.com"));

        List<IScanIssue> iScanIssues =
                scannerCheck.doPassiveScan(iHttpRequestResponse);

        assertTrue(containsUniqueValues(iScanIssues));

        System.setProperty(HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.STOP_AFTER_FIRST_FINDING.toString());
    }
}
