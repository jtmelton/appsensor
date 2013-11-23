package org.owasp.appsensor;

import java.util.Collection;

/**
 * The RequestHandler is the key interface that the server side of 
 * AppSensor implements to handle the different components.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface RequestHandler {
	
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
	 * Retrieve any responses generated that apply to this client application 
	 * since the last time the client application called this method.
	 *  
	 * @return a Collection of Response objects 
	 */
	public Collection<Response> getResponses(String detectionSystemId, long earliest);
	
}
