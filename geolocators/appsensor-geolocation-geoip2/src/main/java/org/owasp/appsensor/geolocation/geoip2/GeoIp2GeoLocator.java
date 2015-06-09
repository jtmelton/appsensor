package org.owasp.appsensor.geolocation.geoip2;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.geolocation.GeoLocation;
import org.owasp.appsensor.core.geolocation.GeoLocator;
import org.owasp.appsensor.core.logging.Loggable;
import org.slf4j.Logger;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.record.Location;

/**
 * This geo locator uses the maxmind geo-ip2 dataset. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.1.0
 */
@Named
@Loggable
public class GeoIp2GeoLocator implements GeoLocator {
	
    private Logger logger;
    
    private static DatabaseReader reader;
    
    @Inject
	private ServerConfiguration serverConfiguration;
    
    @Override
    public GeoLocation readLocation(InetAddress address) {
    	if(reader == null) {
    		initializeDataset();
    	}
    	
    	GeoLocation geoLocation = null;
    	
    	try {
    		if(reader != null) {
				Location location = reader.city(address).getLocation();
				geoLocation = new GeoLocation(location.getLatitude(), location.getLongitude());
    		}
		} catch(IOException | GeoIp2Exception e) {
			if(logger != null) {
				logger.warn("Couldn't locate lat/long for address", e);
			} 
		}
    	
    	return geoLocation;
    }
    
    private void initializeDataset() {
    	if(serverConfiguration.isGeolocateIpAddresses()) {
    		logger.info("Geolocation enabled: attempting to load database from " + serverConfiguration.getGeolocationDatabasePath());
	    	try {
	    		File database = new File(serverConfiguration.getGeolocationDatabasePath());
	    		reader = new DatabaseReader.Builder(database).build();
			} catch(IOException e) {
				if(logger != null) {
					logger.warn("Couldn't load IP address <--> geolocation DB", e);
				} 
			}
    	}
    }
    
}