package com.github.adriancitu.burp.tabnabbing.parser;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
     * Method: getProblem()
     */
    @Test
    public void testGetProblemNoPb() {
        final Optional<TabNabbingProblem> problem = reader.getProblem();

        assertFalse(problem.isPresent());

        //check that the IByteReaderObserver.push and
        //IByteReaderObserver.problemFound was called for each byte frm bytes
        verify(mockListener, times(bytes.length)).push(anyObject(), anyByte());
        verify(mockListener, times(bytes.length)).problemFound();

        verify(mockListener, times(0)).getProblem();
    }

    /**
     * Method: pull(int howManyBytes)
     */
    @Test
    public void testPull() throws Exception {

        //get 1 byte
        byte[] pull = this.reader.pull(1);
        assertEquals(1, pull.length);

        //get all the bytes
        pull = this.reader.pull(bytes.length - 1);
        assertEquals(bytes.length - 1, pull.length);

        //get more bytes than the bufffer
        pull = this.reader.pull(10000);
        assertEquals(bytes.length - 1, pull.length);
    }


} 
