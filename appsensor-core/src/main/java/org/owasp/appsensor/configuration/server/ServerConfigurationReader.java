package org.owasp.appsensor.configuration.server;

import java.text.ParseException;



public interface ServerConfigurationReader {
	
	/**
	 * Read content using default locations
	 * @return populated configuration object
	 * @throws ParseException
	 */
	public ServerConfiguration read() throws ParseException;
	
	/**
	 * 
	 * @param configurationLocation specify configuration location (ie. file location of XML file)
	 * @param validatorLocation specify validator location (ie. file location of XSD file)
	 * @return populated configuration object
	 * @throws ParseException
	 */
	public ServerConfiguration read(String configurationLocation, String validatorLocation) throws ParseException;
}
