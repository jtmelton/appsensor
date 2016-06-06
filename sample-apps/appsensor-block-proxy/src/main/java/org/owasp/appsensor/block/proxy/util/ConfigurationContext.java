package org.owasp.appsensor.block.proxy.util;

import org.owasp.appsensor.block.proxy.BlockProxyConfiguration;

import com.google.common.base.Preconditions;

public class ConfigurationContext {

	private static BlockProxyConfiguration configuration;
	
	public static void set(final BlockProxyConfiguration configurationToSet) {
		if(configuration != null) {
			throw new IllegalStateException("Configuration can only be set once.");
		}
		
		configuration = configurationToSet;
	}
	
	public static BlockProxyConfiguration get() {
		Preconditions.checkNotNull(configuration);
		return configuration;
	}
	
}
