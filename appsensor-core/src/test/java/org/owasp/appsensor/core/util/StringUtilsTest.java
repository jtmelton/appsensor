package org.owasp.appsensor.core.util;

import org.junit.Assert;
import org.junit.Test;

public class StringUtilsTest {

	@Test(expected=java.lang.IllegalArgumentException.class)
	public void testToCollectionNull() {
		StringUtils.toCollection(null);
	}
	
	@Test
	public void testToCollection() {
		Assert.assertEquals(1, StringUtils.toCollection("abc").size());
	}
	
}
