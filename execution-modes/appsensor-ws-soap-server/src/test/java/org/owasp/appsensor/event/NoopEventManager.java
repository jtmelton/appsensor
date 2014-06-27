package org.owasp.appsensor.event;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;

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
	public Collection<Response> getResponses() {
		Collection<Response> responses = new ArrayList<Response>();
		return responses;
	}

}