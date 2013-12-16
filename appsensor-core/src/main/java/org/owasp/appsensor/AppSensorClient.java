package org.owasp.appsensor;

import java.text.ParseException;

import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.StaxClientConfigurationReader;
import org.owasp.appsensor.exceptions.NotBootstrappedException;

/**
 * This class exposes the main interfaces expected to be available 
 * to the client application. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class AppSensorClient extends ObjectFactory {
	
	private static ClientConfigurationReader configurationReader;
	
	private static ClientConfiguration configuration;
	
	private static EventManager eventManager; 

	private static ResponseHandler responseHandler;
	
	private static UserManager userManager;
	
	public static synchronized void bootstrap() {
		bootstrap(new StaxClientConfigurationReader());
	}
	
	public static synchronized void bootstrap(ClientConfigurationReader specifiedConfigurationReader) {
		if (configuration != null) {
			throw new IllegalStateException("Bootstrapping the AppSensorClient should only occur 1 time per JVM instance.");
		}
		
		configurationReader = specifiedConfigurationReader;
		
		try {
			configuration = configurationReader.read();
		} catch(ParseException pe) {
			throw new RuntimeException(pe);
		}
	}
	
	public static AppSensorClient getInstance() {
		if (configuration == null) {
			throw new NotBootstrappedException("AppSensorClient must be bootstrapped before use.");
		}
		
		return SingletonHolder.instance;
	}
	
	private static final class SingletonHolder {
		static final AppSensorClient instance = new AppSensorClient();
	}
	
	//singleton
	private AppSensorClient() { }
	
	public ClientConfiguration getConfiguration() {
		return configuration;
	}
	
	public EventManager getEventManager() {
		if (eventManager == null) {
			eventManager = make(getConfiguration().getEventManagerImplementation(), "EventManager");
		}
		
		return eventManager;
	}
	
	public ResponseHandler getResponseHandler() {
		if (responseHandler == null) {
			responseHandler = make(getConfiguration().getResponseHandlerImplementation(), "ResponseHandler");
		}
		
		return responseHandler;
	}
	
	public UserManager getUserManager() {
		if (userManager == null) {
			userManager = make(getConfiguration().getUserManagerImplementation(), "UserManager");
		}
		
		return userManager;
	}
}
