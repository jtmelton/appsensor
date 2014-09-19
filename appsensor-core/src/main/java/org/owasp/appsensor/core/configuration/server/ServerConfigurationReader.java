package org.owasp.appsensor.core.configuration.server;

import org.owasp.appsensor.core.exceptions.ConfigurationException;

/**
 * This interface is to be fulfilled by implementations that load a configuration 
 * file and provide an object representation of it. 
 * 
 * The current implementation only consists of an XML configuration that utilizes a 
 * standardized XSD schema. However, there is nothing in the interface requiring the 
 * XML implementation. Most standard users will likely stick to the standard implementation. 
 * 
 * TODO: may update this interface is we move to something other than "reading" 
 * the config, ie. supporting configs from data stores/cloud, etc.
 * 
 * @author johnmelton
 */
public interface ServerConfigurationReader {
	
	/**
	 * Read content using default locations
	 * @return populated configuration object
	 * @throws ConfigurationException
	 */
	public ServerConfiguration read() throws ConfigurationException;
	
	/**
	 * 
	 * @param configurationLocation specify configuration location (ie. file location of XML file)
	 * @param validatorLocation specify validator location (ie. file location of XSD file)
	 * @return populated configuration object
	 * @throws ConfigurationException
	 */
	public ServerConfiguration read(String configurationLocation, String validatorLocation) throws ConfigurationException;
}
