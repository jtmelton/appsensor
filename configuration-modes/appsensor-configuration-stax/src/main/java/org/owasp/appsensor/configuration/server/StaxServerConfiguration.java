package org.owasp.appsensor.configuration.server;

import javax.inject.Named;

import org.owasp.appsensor.exceptions.ConfigurationException;
import org.springframework.beans.BeanUtils;

/**
 * Represents the configuration for server-side components. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class StaxServerConfiguration extends ServerConfiguration {

	public StaxServerConfiguration() {
		this(true);
	}
	
	public StaxServerConfiguration(boolean loadConfiguration) {
		if (loadConfiguration) {
			ServerConfiguration configuration = loadConfiguration(new StaxServerConfigurationReader());
			if (configuration != null) {
				BeanUtils.copyProperties(configuration, this);
			}
		}
	}
	
	/**
	 * Bootstrap mechanism that loads the configuration for the server object based 
	 * on the specified configuration reading mechanism. 
	 * 
	 * The reference implementation of the configuration is XML-based, but this interface 
	 * allows for whatever mechanism is desired
	 * 
	 * @param configurationReader desired configuration reader 
	 */
	private ServerConfiguration loadConfiguration(ServerConfigurationReader configurationReader) {
		ServerConfiguration configuration = null;
		
		try {
			configuration = configurationReader.read();
		} catch(ConfigurationException pe) {
			throw new RuntimeException(pe);
		}
		
		return configuration;
	}
}
