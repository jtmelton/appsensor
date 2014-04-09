package org.owasp.appsensor.configuration;

public class ConfigurationParameter {
	
	private String key;
	
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
