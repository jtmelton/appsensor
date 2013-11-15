package org.owasp.appsensor.exceptions;

public class ConfigurationException extends RuntimeException  {

	private static final long serialVersionUID = 538520201225584981L;

	public ConfigurationException(String s) {
		super(s);
	}
	
	public ConfigurationException(String s, Throwable cause) {
		super(s, cause);
	}
	
}
