package org.owasp.appsensor.block.proxy.domain;

import javax.ws.rs.client.Client;

public class JerseyClientCache {
	
	private static Client INSTANCE;
	
	private JerseyClientCache() {}
	
	// should only be called once on initialization
	public static void setInstance(Client client) {
		INSTANCE = client;
	}
	
	public static Client getInstance() {
		return INSTANCE;
	}
	
}
