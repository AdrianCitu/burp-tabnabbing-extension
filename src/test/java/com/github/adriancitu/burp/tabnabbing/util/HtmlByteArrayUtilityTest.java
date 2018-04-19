package com.github.adriancitu.burp.tabnabbing.util;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * HtmlByteArrayUtility Tester.
 *
 * @author Adrian CITU
 * @version 1.0
 * @since <pre>Apr 9, 2018</pre>
 */
public class HtmlByteArrayUtilityTest {

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: tabNabbingProblemFound(final List<Byte> buffer)
     */
    @Test
    public void testTabNabbingProblemFound() throws Exception {
        final String randomString = new String("qwerftyrvfsee HTer fe q");
        assertFalse(HtmlByteArrayUtility.tabNabbingProblemFound(randomString.getBytes()));

        final String hrefWithProblem = new String("<a href=\"bad.example.com\" target=\"_blank\">");
        assertTrue(HtmlByteArrayUtility.tabNabbingProblemFound(hrefWithProblem.getBytes()));

        final String hrefWithNoProblem = new String("<a href=\"bad.example.com\" rel=\"noopener noreferrer\"  target=\"_blank\">");
        assertFalse(HtmlByteArrayUtility.tabNabbingProblemFound(hrefWithNoProblem.getBytes()));

    }

} 
