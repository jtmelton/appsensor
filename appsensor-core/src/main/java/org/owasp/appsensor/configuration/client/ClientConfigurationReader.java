package org.owasp.appsensor.configuration.client;

import java.text.ParseException;



public interface ClientConfigurationReader {
	
	/**
	 * Read content using default locations
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
