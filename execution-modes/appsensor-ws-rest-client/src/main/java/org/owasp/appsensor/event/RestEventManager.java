package org.owasp.appsensor.event;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.configuration.ExtendedConfiguration;

/**
 * This event manager should perform rest style requests since it functions
 * as the reference rest client.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class RestEventManager implements EventManager {

	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
