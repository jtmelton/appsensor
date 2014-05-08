package org.owasp.appsensor.configuration.client;

import javax.inject.Named;

import org.owasp.appsensor.exceptions.ConfigurationException;
import org.springframework.beans.BeanUtils;

/**
 * Represents the configuration for client-side components. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class StaxClientConfiguration extends ClientConfiguration {

	public StaxClientConfiguration() {
		this(true);
	}
	
	public StaxClientConfiguration(boolean loadConfiguration) {
		if (loadConfiguration) {
			ClientConfiguration configuration = loadConfiguration(new StaxClientConfigurationReader());
			if (configuration != null) {
				BeanUtils.copyProperties(configuration, this);
			}
		}
	}
	
	/**
	 * Bootstrap mechanism that loads the configuration for the client object based 
	 * on the specified configuration reading mechanism. 
	 * 
	 * The reference implementation of the configuration is XML-based, but this interface 
	 * allows for whatever mechanism is desired
	 * 
	 * @param configurationReader desired configuration reader 
	 */
	private ClientConfiguration loadConfiguration(ClientConfigurationReader configurationReader) {
		ClientConfiguration configuration = null;
		
		try {
			configuration = configurationReader.read();
		} catch(ConfigurationException pe) {
			throw new RuntimeException(pe);
		}
		
		return configuration;
	}

}
