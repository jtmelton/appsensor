package org.owasp.appsensor.configuration;

/**
 * Represents the key-value pair for a configuration parameter for 
 * custom components to allow additional configuration settings. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ConfigurationParameter {
	
	/** Name (key) of {@link ConfigurationParameter} */
	private String key;
	
	/** Value of {@link ConfigurationParameter} */
	private String value;
	
	public ConfigurationParameter() { }
	
	public ConfigurationParameter(String key, String value) {
		setKey(key);
		setValue(value);
	}

	public String getKey() {
		return key;
	}

	public ConfigurationParameter setKey(String key) {
		this.key = key;
		
		return this;
	}

	public String getValue() {
		return value;
	}

	public ConfigurationParameter setValue(String value) {
		this.value = value;

		return this;
	}

}
