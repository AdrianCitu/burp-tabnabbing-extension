package com.github.adriancitu.burp.tabnabbing.parser;

import com.github.adriancitu.burp.tabnabbing.scanner.IssueType;
import com.github.adriancitu.burp.tabnabbing.scanner.ScanStrategy;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * HTMLAnchorReaderObserver Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Apr 13, 2018</pre>
 */
public class HTMLAnchorReaderListenerTest {

    private IByteReader reader = null;
    private IByteReaderObserver hrefListener = new HTMLAnchorReaderObserver(false);

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }


    @Test
    public void testPushNoHtml() {

        final String noHtml = new String("gfgfgdf fgfgss fs ");
        reader = new HTMLResponseReader(
                noHtml.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertTrue(response.isEmpty());

    }

    @Test
    public void testPushHRefProblem() {

        final String hRefWithProblem = new String("Jump to: <a href=\"#mw-head\">navigation</a>, <a href=\"#p-search\">search</a>\n");

        reader = new HTMLResponseReader(
                hRefWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertEquals(1, response.size());
        assertEquals("<a href=\"#mw-head\">", response.get(0).getProblem());
        assertEquals(IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER, response.get(0).getIssueType());

    }

    @Test
    public void testPushHRefProblemOnSecondAnchor() {

        final String hRefWithProblem = new String("Jump to: <a rel=\"noopener noreferrer\" href=\"#mw-head\">navigation</a>, " +
                "<a href=\"#p-search\">search</a>\n");

        reader = new HTMLResponseReader(
                hRefWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertTrue(response.size() == 1);
        assertEquals("<a href=\"#p-search\">", response.get(0).getProblem());

    }

    @Test
    public void testPushHRefNoProblem() {

        final String hRefWithProblem = new String("Jump to: <a href=\"#mw-head\" rel=\"noopener noreferrer\">navigation </a>\n");

        reader = new HTMLResponseReader(
                hRefWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertTrue(response.isEmpty());

    }


    @Test
    public void testMultipleFindings() throws IOException {

        final Path path = Paths.get("src/test/resources/multipleBadHREFResponse.html");
        final byte[] data = Files.readAllBytes(path);

        System.setProperty(
                HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.SCAN_ENTIRE_PAGE.toString());
        reader = new HTMLResponseReader(data);
        reader.attachObservers(Arrays.asList(hrefListener));


        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertEquals(3, response.size());
        System.setProperty(
                HTMLResponseReader.SCAN_STRATEGY_SYSTEM_PROPERTY,
                ScanStrategy.STOP_AFTER_FIRST_FINDING.toString());
    }

    @Test
    public void testNotValidHref() {

        //the a tag is not well closed.
        final String hRefWithProblem = new String("Jump to: <a href=\"#mw-head rel=\"noopener noreferrer\"</a>\n");

        reader = new HTMLResponseReader(
                hRefWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertTrue(response.isEmpty());
    }

    @Test
    public void testNoopenOutsideAnchorTag() {

        //the attribute is autoside the a tag
        final String hRefWithProblem = new String("Jump to: <a href=\"#mw-head\">navigation rel=\"noopener noreferrer\"</a>\n");

        reader = new HTMLResponseReader(
                hRefWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(hrefListener));

        final List<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblems();

        assertTrue(response.size() == 1);
        assertEquals("<a href=\"#mw-head\">", response.get(0).getProblem());
    }
} 
