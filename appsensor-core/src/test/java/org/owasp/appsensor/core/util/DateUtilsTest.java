package org.owasp.appsensor.core.util;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Assert;
import org.junit.Test;

public class DateUtilsTest {

    @Test
    public void testFromStringNotNull() throws Exception {
        String rfc3339String = "2016-03-08T13:22:53.108Z";
        DateTime expected = new DateTime(rfc3339String, DateTimeZone.UTC);
        DateTime actual = DateUtils.fromString(rfc3339String);

        Assert.assertNotNull(actual);
        Assert.assertEquals(expected, actual);
    }

    @Test
    public void testFromStringNull() throws Exception {
        DateTime actual = DateUtils.fromString(null);

        Assert.assertNull(actual);

    }

    @Test(expected=java.lang.IllegalArgumentException.class)
    public void testFromEmptyString() throws Exception {

        DateUtils.fromString("");

    }
}