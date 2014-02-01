package org.owasp.appsensor;

import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.StaxClientConfigurationReader;
import org.owasp.appsensor.event.EventManager;
import org.owasp.appsensor.exceptions.ConfigurationException;
import org.owasp.appsensor.response.ResponseHandler;
import org.owasp.appsensor.response.UserManager;

/**
 * This class exposes the main interfaces expected to be available 
 * to the client application. 
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class AppSensorClient extends ObjectFactory {
	
	/** accessor for {@link org.owasp.appsensor.configuration.client.ClientConfiguration} */
	private static ClientConfiguration configuration;
	
	/** accessor for {@link org.owasp.appsensor.event.EventManager} */
	private static EventManager eventManager; 

	/** accessor for {@link org.owasp.appsensor.response.ResponseHandler} */
	private static ResponseHandler responseHandler;
	
	/** accessor for {@link org.owasp.appsensor.response.UserManager} */
	private static UserManager userManager;
	
	/**
	 * Bootstrap mechanism that loads the configuration for the client object based 
	 * on the default configuration reading mechanism. 
	 * 
	 * The reference implementation of the configuration is XML-based and a schema is 
	 * available in the appsensor_client_config_VERSION.xsd.
	 */
	public static synchronized void bootstrap() {
		bootstrap(new StaxClientConfigurationReader());
	}
	
	/**
	 * Bootstrap mechanism that loads the configuration for the client object based 
	 * on the specified configuration reading mechanism. 
	 * 
	 * The reference implementation of the configuration is XML-based, but this interface 
	 * allows for whatever mechanism is desired
	 * 
	 * @param configurationReader desired configuration reader 
	 */
	public static synchronized void bootstrap(ClientConfigurationReader configurationReader) {
		if (configuration != null) {
			throw new IllegalStateException("Bootstrapping the AppSensorClient should only occur 1 time per JVM instance.");
		}
		
		try {
			configuration = configurationReader.read();
		} catch(ConfigurationException pe) {
			throw new RuntimeException(pe);
		}
	}
	
	public static AppSensorClient getInstance() {
		if (configuration == null) {
			//if getInstance is called without the bootstrap having been run, just execute the default bootstrapping
			bootstrap();
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
