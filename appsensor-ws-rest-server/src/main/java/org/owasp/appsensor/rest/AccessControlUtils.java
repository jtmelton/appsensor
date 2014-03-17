package org.owasp.appsensor.rest;

import javax.ws.rs.container.ContainerRequestContext;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.accesscontrol.Action;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

public class AccessControlUtils {

	/**
	 * Check authz before performing action.
	 * @param action desired action
	 * @throws NotAuthorizedException thrown if user does not have role.
	 */
	public static void checkAuthorization(Action action, ContainerRequestContext requestContext) throws NotAuthorizedException {
		String clientApplicationName = (String)requestContext.getProperty(RequestHandler.APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);

		ClientApplication clientApplication = AppSensorServer.getInstance().getConfiguration().findClientApplication(clientApplicationName);
		
		org.owasp.appsensor.accesscontrol.Context context = new org.owasp.appsensor.accesscontrol.Context();
		
		AppSensorServer.getInstance().getAccessController().assertAuthorized(clientApplication, action, context);
	}
	
}
