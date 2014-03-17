package org.owasp.appsensor.handler;

import java.util.Collection;

import javax.ws.rs.Consumes;
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
import org.owasp.appsensor.accesscontrol.Action;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.exceptions.NotAuthorizedException;
import org.owasp.appsensor.rest.AccessControlUtils;
import org.owasp.appsensor.util.StringUtils;

/**
 * This is the restful endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Path("/api/v1.0")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class RestRequestHandler implements RequestHandler {

	@Context
	private ContainerRequestContext requestContext;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/events")
	public void addEvent(Event event) throws NotAuthorizedException {
		AccessControlUtils.checkAuthorization(Action.ADD_EVENT, requestContext);
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/attacks")
	public void addAttack(Attack attack) throws NotAuthorizedException {
		AccessControlUtils.checkAuthorization(Action.ADD_ATTACK, requestContext);
		AppSensorServer.getInstance().getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/responses")
	@Produces(MediaType.APPLICATION_JSON)
	public Collection<Response> getResponses(@QueryParam("earliest") Long earliest) throws NotAuthorizedException {
		AccessControlUtils.checkAuthorization(Action.GET_RESPONSES, requestContext);
		
		String clientApplicationName = (String)requestContext.getProperty(APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);

		SearchCriteria criteria = new SearchCriteria().
				setDetectionSystemIds(StringUtils.toCollection(clientApplicationName)).
				setEarliest(earliest);
		
		return AppSensorServer.getInstance().getResponseStore().findResponses(criteria);
	}
	
}
