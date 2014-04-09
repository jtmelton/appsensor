package org.owasp.appsensor.response;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.AppSensorClient;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.logging.Loggable;
import org.slf4j.Logger;

/**
 * This class should only be used as the server-side response handler
 * if you are in local mode. Otherwise, use a NO-OP implementation 
 * on the server-side.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
@Named
@Loggable
public class LocalResponseHandler implements ResponseHandler {

	private Logger logger;
	
	@Inject
	private AppSensorClient appSensorClient;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void handle(Response response) {
		
		if (LOG.equals(response.getAction())) {
			logger.error("Response executed for user:" + response.getUser().getUsername() + 
					" due to event code: " + response.getDetectionPoint().getId() + 
					", Action: Increased Logging");
		} else if (LOGOUT.equals(response.getAction())) {
			logger.error("Response executed for user:" + response.getUser().getUsername() + 
					" due to event code: " + response.getDetectionPoint().getId() + 
					", Action: Logging out malicious account");
			
			appSensorClient.getUserManager().logout(response.getUser());
		} else if (DISABLE_USER.equals(response.getAction())) {
			logger.error("Response executed for user:" + response.getUser().getUsername() + 
					" due to event code: " + response.getDetectionPoint().getId() + 
					", Action: Disabling malicious account");
			
			appSensorClient.getUserManager().logout(response.getUser());
		} else if (DISABLE_COMPONENT_FOR_SPECIFIC_USER.equals(response.getAction())) {
			logger.error("Response executed for user:" + response.getUser().getUsername() + 
					" due to event code: " + response.getDetectionPoint().getId() + 
					", Action: Disabling Component for Specific User");
			
			//TODO: fill in real code for disabling component for specific user
		} else if (DISABLE_COMPONENT_FOR_ALL_USERS.equals(response.getAction())) {
			logger.error("Response executed for user:" + response.getUser().getUsername() + 
					" due to event code: " + response.getDetectionPoint().getId() + 
					", Action: Disabling Component for All Users");
			
			//TODO: fill in real code for disabling component for all users
		} else {
			throw new IllegalArgumentException("There has been a request for an action " +
					"that is not supported by this response handler.  The requested action is: " + response.getAction());
		}
	}

}
