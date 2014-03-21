package org.owasp.appsensor.reporting;

import java.util.Collection;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.accesscontrol.Action;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.exceptions.NotAuthorizedException;
import org.owasp.appsensor.rest.AccessControlUtils;

/**
 * This is the restful endpoint that handles reporting requests on the server-side. 
 * 
 * This simple RESTful implementation queries the appropriate *Store implementations 
 * for matching entities.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Path("/api/v1.0/reports")
@Produces(MediaType.APPLICATION_JSON)
public class RestReportingEngine implements ReportingEngine {

	@Context
	private ContainerRequestContext requestContext;
	
	/**
	 * {@inheritDoc}
	 */
//	@Override
//	public void update(Observable o, Object arg) {
//		//ignore - don't need updates - not collecting notifications here
//	}
	
	@Override
	public void onAdd(Event event) {
//		logger.info("Reporter observed event by user [" + event.getUser().getUsername() + "]");
	}

	@Override
	public void onAdd(Attack attack) {
//		logger.info("Reporter observed attack by user [" + attack.getUser().getUsername() + "]");
	}

	@Override
	public void onAdd(Response response) {
//		logger.info("Reporter observed response for user [" + response.getUser().getUsername() + "]");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/events")
	public Collection<Event> findEvents(@QueryParam("earliest") Long earliest) throws NotAuthorizedException {
		AccessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return AppSensorServer.getInstance().getEventStore().findEvents(criteria);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/attacks")
	public Collection<Attack> findAttacks(@QueryParam("earliest") Long earliest) {
		AccessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return AppSensorServer.getInstance().getAttackStore().findAttacks(criteria);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	@GET
	@Path("/responses")
	public Collection<Response> findResponses(@QueryParam("earliest") Long earliest) {
		AccessControlUtils.checkAuthorization(Action.EXECUTE_REPORT, requestContext);
		
		SearchCriteria criteria = new SearchCriteria().setEarliest(earliest);
		
		return AppSensorServer.getInstance().getResponseStore().findResponses(criteria);
	}
	
}