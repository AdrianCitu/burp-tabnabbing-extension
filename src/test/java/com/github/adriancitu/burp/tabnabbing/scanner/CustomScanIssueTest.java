package com.github.adriancitu.burp.tabnabbing.scanner;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * CustomScanIssue Tester.
 */
public class CustomScanIssueTest {

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
    }

    /**
     * Method: getUrl()
     */
    @Test
    public void testEquals() {

        CustomScanIssue i1 = new CustomScanIssue(
                null,
                null,
                IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER,
                "detail");



        CustomScanIssue i2 = new CustomScanIssue(
                null,
                null,
                IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER,
                "detail");


        Assert.assertTrue(i1.equals(i2));

        CustomScanIssue i3 = new CustomScanIssue(
                null,
                null,
                IssueType.HTML_LINK_NO_REFERRER_POLICY_HEADER,
                "detailNew");

        Assert.assertFalse(i1.equals(i3));
    }


} 
