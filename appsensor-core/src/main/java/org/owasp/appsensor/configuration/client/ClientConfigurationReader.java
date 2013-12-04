package org.owasp.appsensor.configuration.client;

import java.text.ParseException;

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
public interface ClientConfigurationReader {
	
	/**
	 * Read content using default locations of: 
	 * 
	 * XML: /appsensor-client-config.xml
	 * XSD: /appsensor_client_config_2.0.xsd
	 * 
	 * @return populated configuration object
	 * @throws ParseException
	 */
	public ClientConfiguration read() throws ParseException;
	
	/**
	 * 
	 * @param configurationLocation specify configuration location (ie. file location of XML file)
	 * @param validatorLocation specify validator location (ie. file location of XSD file)
	 * @return populated configuration object
	 * @throws ParseException
	 */
	public ClientConfiguration read(String configurationLocation, String validatorLocation) throws ParseException;
}
