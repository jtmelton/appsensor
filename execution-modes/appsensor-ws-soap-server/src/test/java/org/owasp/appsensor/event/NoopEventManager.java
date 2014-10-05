package org.owasp.appsensor.event;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.event.EventManager;

@Named
public class NoopEventManager implements EventManager {
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		//
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		//
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses(String earliest) {
		Collection<Response> responses = new ArrayList<Response>();
		return responses;
	}

}