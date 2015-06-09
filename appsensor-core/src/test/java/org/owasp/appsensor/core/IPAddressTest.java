package org.owasp.appsensor.core;

import org.junit.Assert;
import org.junit.Test;

public class IPAddressTest {
	
	IPAddress ipAddress = new IPAddress();

	@Test(expected=java.lang.IllegalArgumentException.class)
	public void testFromStringInvalidFormat() {
		ipAddress.fromString("1234");
	}
	
	@Test(expected=java.lang.IllegalArgumentException.class)
	public void testFromStringInvalidAddress() {
		ipAddress.fromString("123.123.123.456");
	}
	
	@Test
	public void testFromStringValid() {
		ipAddress.fromString("1.2.3.4");
		ipAddress.fromString("255.255.255.255");
		ipAddress.fromString("2001:cdba:0000:0000:0000:0000:3257:9652");
		ipAddress.fromString("2001:cdba:0:0:0:0:3257:9652");
		ipAddress.fromString("2001:cdba::3257:9652");
	}
	
	@Test
	public void testAsInetAddress() {
		IPAddress a1 = ipAddress.fromString("1.2.3.4");
		Assert.assertEquals("1.2.3.4", a1.asInetAddress().getHostAddress());
		IPAddress a2 = ipAddress.fromString("255.255.255.255");
		Assert.assertEquals("255.255.255.255", a2.asInetAddress().getHostAddress());
		IPAddress a3 = ipAddress.fromString("2001:cdba:0000:0000:0000:0000:3257:9652");
		Assert.assertEquals("2001:cdba:0:0:0:0:3257:9652", a3.asInetAddress().getHostAddress());
		IPAddress a4 = ipAddress.fromString("2001:cdba:0:0:0:0:3257:9652");
		Assert.assertEquals("2001:cdba:0:0:0:0:3257:9652", a4.asInetAddress().getHostAddress());
		IPAddress a5 = ipAddress.fromString("2001:cdba::3257:9652");
		Assert.assertEquals("2001:cdba:0:0:0:0:3257:9652", a5.asInetAddress().getHostAddress());
	}
	
}
