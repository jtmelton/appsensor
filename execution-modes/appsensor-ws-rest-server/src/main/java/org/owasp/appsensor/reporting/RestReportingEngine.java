package org.owasp.appsensor.reporting;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.accesscontrol.Action;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;
import org.owasp.appsensor.core.reporting.ReportingEngine;
import org.owasp.appsensor.rest.AccessControlUtils;

/**
 * This is the restful endpoint that handles reporting requests on the server-side. 
 * 
 * This simple RESTful implementation queries the appropriate *Store implementations 
 * for matching entities.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Path("/api/v1.0/reports")
@Produces(MediaType.APPLICATION_JSON)
@Named
public class RestReportingEngine implements ReportingEngine {

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
	public void onAdd(Event event) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) { }

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) { }
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/events")
	public Collection<Event> findEvents(@QueryParam("earliest") String earliest) throws NotAuthorizedException {
		accessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return appSensorServer.getEventStore().findEvents(criteria);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/attacks")
	public Collection<Attack> findAttacks(@QueryParam("earliest") String earliest) {
		accessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return appSensorServer.getAttackStore().findAttacks(criteria);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/responses")
	public Collection<Response> findResponses(@QueryParam("earliest") String earliest) {
		accessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return appSensorServer.getResponseStore().findResponses(criteria);
	}
	
}