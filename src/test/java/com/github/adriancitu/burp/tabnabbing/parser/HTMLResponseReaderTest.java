package com.github.adriancitu.burp.tabnabbing.parser;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

/**
 * HTMLResponseReader Tester.
 *
 * @author Adrian CITU
 * @version 1.0
 * @since <pre>Apr 12, 2018</pre>
 */
public class HTMLResponseReaderTest {


    private IByteReaderObserver mockListener = mock(IByteReaderObserver.class);

    private HTMLResponseReader reader = null;

    private String someBytes = new String("some bytes bla, bla");
    private byte[] bytes = someBytes.getBytes();

    @Before
    public void before() throws Exception {
        when(mockListener.problemFound()).thenReturn(false);
        when(mockListener.getProblem()).thenReturn(null);
        reader = new HTMLResponseReader(bytes);
        reader.attachObservers(Arrays.asList(mockListener));

    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: getProblems()
     */
    @Test
    public void testGetProblemNoPb() {
        final List<TabNabbingProblem> problem = reader.getProblems();

        assertTrue(problem.isEmpty());

        //check that the IByteReaderObserver.handleByte and
        //IByteReaderObserver.problemFound was called for each byte frm bytes
        verify(mockListener, times(bytes.length)).handleByte(anyObject(), anyByte());
        verify(mockListener, times(bytes.length)).problemFound();

        verify(mockListener, times(0)).getProblem();
    }

    /**
     * Method: fetchMoreBytes(int howManyBytes)
     */
    @Test
    public void testPull() throws Exception {

        //get 1 byte
        byte[] pull = this.reader.fetchMoreBytes(1);
        assertEquals(1, pull.length);

        //get all the bytes
        pull = this.reader.fetchMoreBytes(bytes.length - 1);
        assertEquals(bytes.length - 1, pull.length);

        //get more bytes than the bufffer
        pull = this.reader.fetchMoreBytes(10000);
        assertEquals(bytes.length - 1, pull.length);
    }


} 
