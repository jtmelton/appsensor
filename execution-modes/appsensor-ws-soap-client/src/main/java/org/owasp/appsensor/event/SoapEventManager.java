package org.owasp.appsensor.event;

import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;

/**
 * This event manager should perform soap style requests since it functions
 * as the reference soap client.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class SoapEventManager implements EventManager {

	//TODO: do a soap request based on configuration 
	
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
