package org.owasp.appsensor.handler;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;
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
import org.owasp.appsensor.rest.filter.ClientApplicationIdentificationFilter;
import org.owasp.appsensor.util.StringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * This is the restful endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Path("/api/v1.0")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Named
public class RestRequestHandler implements RequestHandler {

	@Inject
	private AppSensorServer appSensorServer;
	
	@Inject
	private AccessControlUtils accessControlUtils;
	
	@Context
	private ContainerRequestContext requestContext;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/events")
	@ResponseStatus( HttpStatus.CREATED )
	public void addEvent(Event event) throws NotAuthorizedException {
		accessControlUtils.checkAuthorization(Action.ADD_EVENT, requestContext);
		
		event.setDetectionSystemId(getClientApplicationName());
		
		appSensorServer.getEventStore().addEvent(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@POST
	@Path("/attacks")
	@ResponseStatus( HttpStatus.CREATED )
	public void addAttack(Attack attack) throws NotAuthorizedException {
		accessControlUtils.checkAuthorization(Action.ADD_ATTACK, requestContext);
		
		attack.setDetectionSystemId(getClientApplicationName());
		
		appSensorServer.getAttackStore().addAttack(attack);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/responses")
	public Collection<Response> getResponses(@QueryParam("earliest") String earliest) throws NotAuthorizedException {
		accessControlUtils.checkAuthorization(Action.GET_RESPONSES, requestContext);

		SearchCriteria criteria = new SearchCriteria().
				setDetectionSystemIds(StringUtils.toCollection(getClientApplicationName())).
				setEarliest(earliest);

		return appSensorServer.getResponseStore().findResponses(criteria);
	}
	
	/**
	 * Helper method to retrieve client application name.
	 * This is set by the {@link ClientApplicationIdentificationFilter} 
	 * 
	 * @return client application name
	 */
	private String getClientApplicationName() {
		String clientApplicationName = (String)requestContext.getProperty(APPSENSOR_CLIENT_APPLICATION_IDENTIFIER_ATTR);
		
		return clientApplicationName;
	}
	
}
