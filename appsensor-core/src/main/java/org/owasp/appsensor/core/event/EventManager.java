package org.owasp.appsensor.core.event;

import java.util.Collection;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;

/**
 * The EventManager is the key interface that the {@link ClientApplication} accesses to 
 * interact with AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface EventManager {
	
	/**
	 * Add an {@link Event}.
	 * 
	 * @param event {@link Event} to add
	 */
	public void addEvent(Event event);
	
	/**
	 * Add an {@link Attack}
	 * @param attack {@link Attack} to add
	 */
	public void addAttack(Attack attack);

	/**
	 * Retrieve any {@link Response}s generated that apply to this 
	 * client since the last time the client called this method.
	 *  
	 * @return a Collection of {@link Response} objects 
	 */
	public Collection<Response> getResponses();
}
