package org.owasp.appsensor;

import java.text.ParseException;

import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.XmlClientConfigurationReader;

public class ClientObjectFactory extends BaseObjectFactory {
	
	private static ClientConfigurationReader configurationReader;
	
	private static ClientConfiguration configuration;
	
	private static EventManager eventManager; 

	private static ResponseHandler responseHandler;
	
	private static UserManager userManager;
	
	static {
		if(configurationReader == null) {
			configurationReader = new XmlClientConfigurationReader();
		}
		
		if(configuration == null) {
			try {
				configuration = configurationReader.read();
			} catch(ParseException pe) {
				throw new RuntimeException(pe);
			}
		}
	}
	
	//singleton
	private ClientObjectFactory() { }
	
	public static ClientConfiguration getConfiguration() {
		return configuration;
	}
	
	public static EventManager getEventManager() {
		if (eventManager == null) {
			eventManager = make(getConfiguration().getEventManagerImplementation(), "EventManager");
		}
		
		return eventManager;
	}
	
	public static ResponseHandler getResponseHandler() {
		if (responseHandler == null) {
			responseHandler = make(getConfiguration().getResponseHandlerImplementation(), "ResponseHandler");
		}
		
		return responseHandler;
	}
	
	public static UserManager getUserManager() {
		if (userManager == null) {
			userManager = make(getConfiguration().getUserManagerImplementation(), "UserManager");
		}
		
		return userManager;
	}
}
