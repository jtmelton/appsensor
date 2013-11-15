package org.owasp.appsensor.event.impl;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.EventManager;
import org.owasp.appsensor.Response;

/**
 * 
 * @author jtmelton
 *
 */
public class RestEventManager implements EventManager {

	//TODO: do a rest request based on configuration 
	
	@Override
	public void addEvent(Event event) {
		//make request
	}
	
	public void addAttack(Attack attack) {
		//make request
	}
	
	@Override
	public Collection<Response> getResponses() {
		//make request
		return null;
	}

}
