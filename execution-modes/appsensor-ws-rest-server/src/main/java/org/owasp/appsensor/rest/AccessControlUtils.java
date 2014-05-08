package org.owasp.appsensor.rest;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.container.ContainerRequestContext;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.accesscontrol.Action;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This is a simple helper class for performing access control checks for REST requests.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class AccessControlUtils {

	@Inject
	private AppSensorServer appSensorServer;
	
	/**
	 * Check authz before performing action.
	 * @param action desired action
	 * @throws NotAuthorizedException thrown if user does not have role.
	 */
	public void checkAuthorization(Action action, ContainerRequestContext requestContext) throws NotAuthorizedException {
		String clientApplicationName = (String)requestContext.getProperty(RequestHandler.APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);

		ClientApplication clientApplication = appSensorServer.getConfiguration().findClientApplication(clientApplicationName);
		
		org.owasp.appsensor.accesscontrol.Context context = new org.owasp.appsensor.accesscontrol.Context();
		
		appSensorServer.getAccessController().assertAuthorized(clientApplication, action, context);
	}
	
}
