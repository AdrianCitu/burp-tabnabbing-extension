package com.github.adriancitu.burp.tabnabbing.parser;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Optional;

import static junit.framework.TestCase.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * JSWindowsOpenReaderObserver Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>Apr 16, 2018</pre>
 */
public class JSWindowsOpenReaderObserverTest {

    private IByteReader reader = null;
    private IByteReaderObserver jsListener = new JSWindowsOpenReaderObserver();

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }


    @Test
    public void testPushNoJavaSCript() {

        final String noHtml = new String("xcvxcvxc xxcvv zxc ");
        reader = new HTMLResponseReader(
                noHtml.getBytes());
        reader.attachObservers(Arrays.asList(jsListener));

        final Optional<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblem();

        assertFalse(response.isPresent());

    }


    @Test
    public void testWindowOpenNotInsideScript (){
        {
            final String jsWithProblem = "<body>\n" +
                    "<li><a href=\"bad.example.com\" rel=\"noopener\" target=\"_blank\">Vulnerable target using html link to open the new page</a></li>\n" +
                    "<script>dddd</script><button onclick=\"window.open('https://bad.example.com');\">Vulnerable target using javascript to open the new page</button>\n" +
                    "</body>";

            reader = new HTMLResponseReader(
                    jsWithProblem.getBytes());
            reader.attachObservers(Arrays.asList(jsListener));

            final Optional<TabNabbingProblem> response =
                    ((HTMLResponseReader) reader).getProblem();

            assertFalse(response.isPresent());
         }
    }


    @Test
    public void testPushJavaScriptProblem() {
        final String jsWithProblem = "<body>\n" +
                "<li><a href=\"bad.example.com\" rel=\"noopener\" target=\"_blank\">Vulnerable target using html link to open the new page</a></li>\n" +
                "<script><button onclick=\"window.open('https://bad.example.com');\">Vulnerable target using javascript to open the new page</button>\n" +
                "</script>\n" +
                "</body>";

        reader = new HTMLResponseReader(
                jsWithProblem.getBytes());
        reader.attachObservers(Arrays.asList(jsListener));

        final Optional<TabNabbingProblem> response =
                ((HTMLResponseReader) reader).getProblem();

        assertTrue(response.isPresent());
        assertEquals(
                "window.open('https://bad.example.com');",
                response.get().getProblem());
    }

    @Test
    public void testWindowNoProblem (){
        {
            final String jsWithProblem = "<body>\n" +
                    "<li><a href=\"bad.example.com\" rel=\"noopener\" target=\"_blank\">Vulnerable target using html link to open the new page</a></li>\n" +
                    "<script><button onclick=\"window.open('https://bad.example.com', 'noopener ,noreferrer' );\">Vulnerable target using javascript to open the new page</button>\n" +
                    "</script>" +
                    "</body>";

            reader = new HTMLResponseReader(
                    jsWithProblem.getBytes());
            reader.attachObservers(Arrays.asList(jsListener));

            final Optional<TabNabbingProblem> response =
                    ((HTMLResponseReader) reader).getProblem();

            assertFalse(response.isPresent());
        }
    }
} 
