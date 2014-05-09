package org.owasp.appsensor.event;

import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;

/**
 * This event manager should perform rest style requests since it functions
 * as the reference rest client.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
public class RestEventManager implements EventManager {

	//TODO: do a rest request based on configuration 
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		//make request
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		//make request
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses() {
		//make request
		return null;
	}

}
