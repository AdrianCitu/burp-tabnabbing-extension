package com.github.adriancitu.burp.tabnabbing.util;

import com.github.adriancitu.burp.tabnabbing.util.HtmlByteArrayUtility;
import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
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
     * Method: getFirstTabNabbingProblem(byte[] byteList)
     */
    @Test
    public void testGetFirstTabNabbingHTMLProblem() throws Exception {
        final Path path = Paths.get("src/test/resources/badHREFResponse.html");
        final byte[] data = Files.readAllBytes(path);

        final Optional<byte[]> result = HtmlByteArrayUtility.getFirstTabNabbingProblem(data);

        assertTrue(result.isPresent());

        assertEquals(
                "<a href=\"bad.example.com\" target=\"_blank\">",
                new String(result.get()));
    }

    @Test
    public void testGetFirstTabNabbingJSProblem() throws Exception {
        final Path path = Paths.get("src/test/resources/badJSResponse.html");
        final byte[] data = Files.readAllBytes(path);

        final Optional<byte[]> result = HtmlByteArrayUtility.getFirstTabNabbingProblem(data);

        assertTrue(result.isPresent());

        assertEquals(
                "window.open('https://bad.example.com');",
                new String(result.get()));
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

    /**
     * Method: foundWindowsOpen(byte[] source, int i)
     */
    @Test
    public void testFoundWindowsOpen() throws Exception {

        final String noJs = new String("weqeqweqw ff ccaaa cas <> S<wi f");
        assertFalse(HtmlByteArrayUtility.foundWindowsOpen(noJs.getBytes(), 0));

        final String jsWithNoOpen = new String("(function (i, s, o, g, r, a, m) {\n" +
                "        i['GoogleAnalyticsObject'] = r;\n" +
                "        i[r] = i[r] || function () {\n" +
                "            (i[r].q = i[r].q || []).push(arguments)\n" +
                "        }, i[r].l = 1 * new Date();\n" +
                "        a = s.createElement(o),\n" +
                "            m = s.getElementsByTagName(o)[0];");

        assertFalse(HtmlByteArrayUtility.foundWindowsOpen(jsWithNoOpen.getBytes(), 0));

        final String jsWithOpen = new String("window.RLQ = window.RLQ || [])." +
                "push(function () {mw.loader.state({\"user\": \"ready\", " +
                "\"user.groups\": \"ready\"});mw.loader.load([\"mediawiki.toc\", " +
                "\"mediawiki.action.view.postEdit\", \"site\", \"mediawiki.user\", " +
                "\"mediawiki.hidpi\", \"mediawiki.page.ready\", \"mediawiki." +
                "searchSuggest\",\"ext.headertabs\", \"ext.visualEditor.targetLoader\"]); window.open(ffff, fffff,fffff);}");

        assertTrue(HtmlByteArrayUtility.foundWindowsOpen(jsWithOpen.getBytes(), 323));


    }

    /**
     * Method: foundHref(byte[] source, int i)
     */
    @Test
    public void testFoundHref() throws Exception {

        final String noHref = new String("werewr ffsddsfsd aaaa dddas<ff>");
        assertFalse(HtmlByteArrayUtility.foundHref(noHref.getBytes(), 0));


        final String htmlHref = new String("<!DOCTYPE html>\n" +
                "<html lang=\"en\" dir=\"ltr\" class=\"client-nojs\">\n" +
                "<head>\n" +
                "    <meta charset=\"UTF-8\"/>\n" +
                "    <link rel=\"alternate\" type=\"application/atom+xml\" title=\"OWASP Atom feed\" href=\"/index.php?title=Special:RecentChanges&amp;feed=atom\"/>\n" +
                "</head>\n" +
                "\n" +
                "<body>\n" +
                "<li><a href=\"bad.example.com\" target=\"_blank\">Vulnerable target using html link to open the new page</a></li>\n" +
                "<button onclick=\"window.open('https://bad.example.com')\">Vulnerable target using javascript to open the new page</button>\n" +
                "</body>\n" +
                "\n" +
                "</html>\n");

        assertFalse(HtmlByteArrayUtility.foundHref(htmlHref.getBytes(),0));
        assertTrue(HtmlByteArrayUtility.foundHref(htmlHref.getBytes(),259));


    }

    /**
     * Method: foundScriptTag(byte[] source, int i)
     */
    @Test
    public void testFoundScriptTag() throws Exception {
        final String htmlWithScript = new String("</div>\n" +
                "<script>(window.RLQ = window.RLQ || []).push(function () {\n" +
                "    mw.loader.state({\"user\": \"ready\", \"user.groups\": \"ready\"});\n" +
                "    mw.loader.load([\"mediawiki.toc\", \"mediawiki.action.view.postEdit\", \"site\", \"mediawiki.user\", \"mediawiki.hidpi\", \"mediawiki.page.ready\", \"mediawiki.searchSuggest\", \"ext.headertabs\", \"ext.visualEditor.targetLoader\"]);\n" +
                "});</script>\n" +
                "<script>");

        assertFalse(HtmlByteArrayUtility.foundScriptTag(htmlWithScript.getBytes(), 0));
        assertTrue(HtmlByteArrayUtility.foundScriptTag(htmlWithScript.getBytes(),8));
    }

} 
