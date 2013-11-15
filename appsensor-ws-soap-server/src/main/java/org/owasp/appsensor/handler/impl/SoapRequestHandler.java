package org.owasp.appsensor.handler.impl;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.RequestHandler;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

/**
 * This is the soap endpoint that handles requests on the server-side. 
 * 
 * @author jtmelton
 */
public class SoapRequestHandler implements RequestHandler {

	//TODO: add ws server-side handlers here 
	
	@Override
	public void addEvent(Event event) {
		ServerObjectFactory.getEventStore().addEvent(event);
	}

	@Override
	public void addAttack(Attack attack) {
		ServerObjectFactory.getAttackStore().addAttack(attack);
	}

	@Override
	public Collection<Response> getResponses(String detectionSystemId, long earliest) {
		return ServerObjectFactory.getResponseStore().findResponses(detectionSystemId, earliest);
	}

}
