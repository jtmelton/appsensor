package org.owasp.appsensor.core;

import javax.inject.Inject;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class IPAddressGeoLocationTest {

	@Inject 
	private IPAddress ipAddress;
	
	@Test
	public void testGeoLocationInfo() {
		// russia
		IPAddress a1 = ipAddress.fromString("5.45.80.10");	
		Assert.assertEquals(55.7522, a1.getGeoLocation().getLatitude(), 1.0);
		Assert.assertEquals(37.6156, a1.getGeoLocation().getLongitude(), 1.0);
		// canada
		IPAddress a2 = ipAddress.fromString("23.29.201.141");
		Assert.assertEquals(60.0, a2.getGeoLocation().getLatitude(), 1.0);
		Assert.assertEquals(-95.0, a2.getGeoLocation().getLongitude(), 1.0);
		// australia
		IPAddress a3 = ipAddress.fromString("27.54.137.119");
		Assert.assertEquals(-27.0, a3.getGeoLocation().getLatitude(), 1.0);
		Assert.assertEquals(133.0, a3.getGeoLocation().getLongitude(), 1.0);
		// south africa
		IPAddress a4 = ipAddress.fromString("41.50.10.35");
		Assert.assertEquals(-29.0, a4.getGeoLocation().getLatitude(), 1.0);
		Assert.assertEquals(24.0, a4.getGeoLocation().getLongitude(), 1.0);
	}
	
}
