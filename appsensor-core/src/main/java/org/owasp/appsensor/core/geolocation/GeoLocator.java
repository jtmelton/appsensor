package org.owasp.appsensor.core.geolocation;

import java.net.InetAddress;

/**
 * A geo-locator performs a lookup of an IP address and converts it to a {@link GeoLocation}. 
 * 
 * Different implementations will use different geo-location libraries.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.1.0
 */
public interface GeoLocator {
	
	/**
	 * Perform a lookup of an IP address and return a {@link GeoLocation}.
	 * 
	 * @param address IP address to geolocate
	 * 
	 * @return populated {@link GeoLocation} object.
	 */
	public GeoLocation readLocation(InetAddress address);
	
}
