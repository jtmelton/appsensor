package org.owasp.appsensor.handler.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.GregorianCalendar;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

/**
 * This is the restful endpoint that handles requests on the server-side. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Path("/api/v1.0")
@Produces("application/json")
public class RestRequestHandler implements RequestHandler {

	//TODO: add rest server-side handlers here 
	
	@Override
	@POST
	@Path("/events")
	public void addEvent(Event event) {
		ServerObjectFactory.getEventStore().addEvent(event);
	}

	@Override
	@POST
	@Path("/attacks")
	public void addAttack(Attack attack) {
		ServerObjectFactory.getAttackStore().addAttack(attack);
	}

	@Override
	@GET
	@Path("/responses")
	@Produces(MediaType.APPLICATION_JSON)
	public Collection<Response> getResponses(@QueryParam("detectionSystemId") String detectionSystemId, @QueryParam("earliest") long earliest) {
		Collection<Response> responses = new ArrayList<Response>();
		
		Response response1 = new Response();
		response1.setAction("log");
		response1.setDetectionSystemId("server1");
		response1.setTimestamp(new GregorianCalendar().getTimeInMillis() - 30);
		responses.add(response1);
		
		Response response2 = new Response();
		response2.setAction("logout");
		response2.setDetectionSystemId("server2");
		response2.setTimestamp(new GregorianCalendar().getTimeInMillis() - 15);
		responses.add(response2);
		
		Response response3 = new Response();
		response3.setAction("disable");
		response3.setDetectionSystemId("server2");
		response3.setTimestamp(new GregorianCalendar().getTimeInMillis() + 10);
		responses.add(response3);
		
		return responses;
//		return ServerObjectFactory.getResponseStore().findResponses(detectionSystemId, earliest);
	}
}
