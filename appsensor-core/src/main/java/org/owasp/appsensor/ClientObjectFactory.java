package org.owasp.appsensor;

import java.text.ParseException;

import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.StaxClientConfigurationReader;

/**
 * This class exposes the main interfaces expected to be available 
 * to the client application. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ClientObjectFactory extends BaseObjectFactory {
	
	private static ClientConfigurationReader configurationReader;
	
	private static ClientConfiguration configuration;
	
	private static EventManager eventManager; 

	private static ResponseHandler responseHandler;
	
	private static UserManager userManager;
	
	static {
		if(configurationReader == null) {
			configurationReader = new StaxClientConfigurationReader();
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
