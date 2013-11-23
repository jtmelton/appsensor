package org.owasp.appsensor;

import java.util.Collection;

/**
 * The EventManager is the key interface that the client application accesses to 
 * interact with AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface EventManager {
	
	/**
	 * Add an Event.
	 * 
	 * @param event Event to add
	 */
	public void addEvent(Event event);
	
	/**
	 * Add an Attack
	 * @param attack Attack to add
	 */
	public void addAttack(Attack attack);

	/**
	 * Retrieve any responses generated that apply to this 
	 * client since the last time the client called this method.
	 *  
	 * @return a Collection of Response objects 
	 */
	public Collection<Response> getResponses();
}
