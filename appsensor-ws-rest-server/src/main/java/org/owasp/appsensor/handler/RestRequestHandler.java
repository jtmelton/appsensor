package org.owasp.appsensor.handler;

import java.util.Collection;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.accesscontrol.Action;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This is the restful endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Path("/api/v1.0")
@Produces("application/json")
public class RestRequestHandler implements RequestHandler {

	public static String APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR = "APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR";
	
	@Context
	private ContainerRequestContext requestContext;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/events")
	public void addEvent(Event event) throws NotAuthorizedException {
		checkAuthorization(Action.ADD_EVENT);
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/attacks")
	public void addAttack(Attack attack) throws NotAuthorizedException {
		checkAuthorization(Action.ADD_ATTACK);
		AppSensorServer.getInstance().getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/responses")
	@Produces(MediaType.APPLICATION_JSON)
	public Collection<Response> getResponses(@QueryParam("earliest") long earliest) throws NotAuthorizedException {
		checkAuthorization(Action.GET_RESPONSES);
		
		String clientApplicationName = (String)requestContext.getProperty(APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);
		return AppSensorServer.getInstance().getResponseStore().findResponses(clientApplicationName, earliest);
	}
	
	/**
	 * Check authz before performing action.
	 * @param action desired action
	 * @throws NotAuthorizedException thrown if user does not have role.
	 */
	private void checkAuthorization(Action action) throws NotAuthorizedException {
		String clientApplicationName = (String)requestContext.getProperty(APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);

		ClientApplication clientApplication = AppSensorServer.getInstance().getConfiguration().findClientApplication(clientApplicationName);
		
		org.owasp.appsensor.accesscontrol.Context context = new org.owasp.appsensor.accesscontrol.Context();
		
		AppSensorServer.getInstance().getAccessController().assertAuthorized(clientApplication, action, context);
	}
}
