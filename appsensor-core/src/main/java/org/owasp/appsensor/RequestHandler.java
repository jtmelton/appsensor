package org.owasp.appsensor;

import java.util.Collection;


public interface RequestHandler {
	
	public void addEvent(Event event);
	
	public void addAttack(Attack attack);
	
	/**
	 * Retrieve any response generated that apply to this 
	 * client since the last time the client called this method. 
	 */
	public Collection<Response> getResponses(String detectionSystemId, long earliest);
	
}
