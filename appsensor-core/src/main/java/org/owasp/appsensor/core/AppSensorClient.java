package org.owasp.appsensor.core;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.configuration.client.ClientConfiguration;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.response.ResponseHandler;
import org.owasp.appsensor.core.response.UserManager;
import org.slf4j.Logger;

/**
 * AppSensor core class for accessing client-side components. Most components
 * are discoverd via DI. However, the configuration portions are setup in 
 * the appsensor-client-config.xml file.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class AppSensorClient {
	
	@SuppressWarnings("unused")
	private Logger logger;
	
	/** accessor for {@link org.owasp.appsensor.core.configuration.client.ClientConfiguration} */
	private ClientConfiguration configuration;
	
	/** accessor for {@link org.owasp.appsensor.core.event.EventManager} */
	private EventManager eventManager; 

	/** accessor for {@link org.owasp.appsensor.core.response.ResponseHandler} */
	private ResponseHandler responseHandler;
	
	/** accessor for {@link org.owasp.appsensor.core.response.UserManager} */
	private UserManager userManager;
	
	public AppSensorClient() { }
	
	public ClientConfiguration getConfiguration() {
		return configuration;
	}
	
	@Inject
	public void setConfiguration(ClientConfiguration updatedConfiguration) {
		configuration = updatedConfiguration;
	}

	public EventManager getEventManager() {
		return eventManager;
	}

	@Inject
	public void setEventManager(EventManager eventManager) {
		this.eventManager = eventManager;
	}

	public ResponseHandler getResponseHandler() {
		return responseHandler;
	}

	@Inject
	public void setResponseHandler(ResponseHandler responseHandler) {
		this.responseHandler = responseHandler;
	}

	public UserManager getUserManager() {
		return userManager;
	}

	@Inject
	public void setUserManager(UserManager userManager) {
		this.userManager = userManager;
	}
	
}
