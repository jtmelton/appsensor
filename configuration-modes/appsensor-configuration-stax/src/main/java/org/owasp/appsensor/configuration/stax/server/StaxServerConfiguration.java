package org.owasp.appsensor.configuration.stax.server;

import java.io.InputStream;

import javax.inject.Named;

import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.core.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;

/**
 * Represents the configuration for server-side components. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class StaxServerConfiguration extends ServerConfiguration {

	//This needs to be manually setup (not @Loggable) b/c it's used in constructor
	//so the post-processor won't run before it's used - will get NPE
	private Logger logger = LoggerFactory.getLogger(getClass());
		
	public StaxServerConfiguration() {
		this(true);
	}
	
	public StaxServerConfiguration(boolean loadConfiguration) {
		if (loadConfiguration) {
			try {
				ServerConfiguration configuration = loadConfiguration(new StaxServerConfigurationReader());
				
				if (configuration != null) {
					BeanUtils.copyProperties(configuration, this);
				}
			} catch (ConfigurationException e) {
				InputStream inputStream = this.getClass().getClassLoader()
                        .getResourceAsStream("appsensor-client-config.xml");
				if (inputStream != null) {
					//report quiet error if we find the server config on the filesystem
					logger.warn("Could not load appsensor server configuration file. "
							+ "This error is fine if you are running a client.");
				} else {
					//report noisy error if we can't find the server config on the filesystem
					logger.warn("Could not load appsensor server configuration file.", e);
				}
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
	private ServerConfiguration loadConfiguration(ServerConfigurationReader configurationReader) throws ConfigurationException {
		ServerConfiguration configuration = configurationReader.read();
		
		return configuration;
	}
}
