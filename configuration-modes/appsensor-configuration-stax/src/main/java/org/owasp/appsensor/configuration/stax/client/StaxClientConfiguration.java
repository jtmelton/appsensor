package org.owasp.appsensor.configuration.stax.client;

import java.io.InputStream;

import javax.inject.Named;

import org.owasp.appsensor.core.configuration.client.ClientConfiguration;
import org.owasp.appsensor.core.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.core.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

/**
 * Represents the configuration for client-side components. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class StaxClientConfiguration extends ClientConfiguration {
	
	//This needs to be manually setup (not @Loggable) b/c it's used in constructor
	//so the post-processor won't run before it's used - will get NPE
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	public StaxClientConfiguration() {
		this(true);
	}
	
	public StaxClientConfiguration(boolean loadConfiguration) {
		if (loadConfiguration) {
			try {
				ClientConfiguration configuration = loadConfiguration(new StaxClientConfigurationReader());
				
				if (configuration != null) {
					BeanUtils.copyProperties(configuration, this);
				}
			} catch (ConfigurationException e) {
				InputStream inputStream = this.getClass().getClassLoader()
                        .getResourceAsStream("appsensor-server-config.xml");
				if (inputStream != null) {
					//report quiet error if we find the server config on the filesystem
					logger.warn("Could not load appsensor client configuration file. "
							+ "This error is fine if you are running a server.");
				} else {
					//report noisy error if we can't find the server config on the filesystem
					logger.warn("Could not load appsensor client configuration file.", e);
				}
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
	private ClientConfiguration loadConfiguration(ClientConfigurationReader configurationReader) throws ConfigurationException {
		ClientConfiguration configuration = configurationReader.read();
		
		return configuration;
	}

}
