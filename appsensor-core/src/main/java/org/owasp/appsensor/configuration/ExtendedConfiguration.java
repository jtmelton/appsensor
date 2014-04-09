package org.owasp.appsensor.configuration;

import java.util.Collection;
import java.util.HashSet;

import org.apache.commons.lang3.StringUtils;

public class ExtendedConfiguration {

	public Collection<ConfigurationParameter> configurationParameters = new HashSet<>();
	
	public Collection<ConfigurationParameter> getConfigurationParameters() {
		return configurationParameters;
	}
	
	public String findValue(String key, String defaultValue) {
		String value = defaultValue;
		
		for (ConfigurationParameter parameter : getConfigurationParameters()) {
			if (parameter != null && key.equals(parameter.getKey())) {
				if (! StringUtils.isEmpty(parameter.getValue())) {
					value = parameter.getValue();
				}
			}
		}
			
		return value;
	}
	
}
