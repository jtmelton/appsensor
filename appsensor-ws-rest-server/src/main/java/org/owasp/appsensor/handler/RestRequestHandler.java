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
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.exceptions.NotAuthorizedException;

/**
 * This is the restful endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Path("/api/v1.0")
@Produces("application/json")
public class RestRequestHandler implements RequestHandler {

	public static String CLIENT_APPLICATION_IDENTIFIER_ATTR = "APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR";
	
	@Context
	ContainerRequestContext context;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/events")
	public void addEvent(Event event) throws NotAuthorizedException {
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/attacks")
	public void addAttack(Attack attack) throws NotAuthorizedException {
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
		String detectionSystemId = (String)context.getProperty(CLIENT_APPLICATION_IDENTIFIER_ATTR);

		return AppSensorServer.getInstance().getResponseStore().findResponses(detectionSystemId, earliest);
	}
}
