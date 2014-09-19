package org.owasp.appsensor.rest;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.container.ContainerRequestContext;

import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.RequestHandler;
import org.owasp.appsensor.core.accesscontrol.Action;
import org.owasp.appsensor.core.accesscontrol.Context;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;

/**
 * This is a simple helper class for performing access control checks for REST requests.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
public class AccessControlUtils {

	@Inject
	private AppSensorServer appSensorServer;
	
	/**
	 * Check authz before performing action.
	 * 
	 * @param action desired action
	 * @throws NotAuthorizedException thrown if user does not have role.
	 */
	public void checkAuthorization(Action action, ContainerRequestContext requestContext) throws NotAuthorizedException {
		String clientApplicationName = (String)requestContext.getProperty(RequestHandler.APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);

		ClientApplication clientApplication = appSensorServer.getConfiguration().findClientApplication(clientApplicationName);
		
		appSensorServer.getAccessController().assertAuthorized(clientApplication, action, new Context());
	}
	
}
