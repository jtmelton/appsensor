package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.User;

/**
 * A store is an implementation of the Observable pattern. 
 * 
 * It is watched by implementations of the {@link java.util.Observer} interface. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public abstract class ResponseStore extends Observable {
	
	/**
	 * Add a response to the ResponseStore
	 * 
	 * @param response Response to add to the ResponseStore
	 */
	public abstract void addResponse(Response response);
	
	/**
	 * Finder for responses in the ResponseStore
	 * 
	 * @param user User object to search by
	 * @param detectionPoint DetectionPoint object to search by
	 * @param detectionSystemIds Collection of detection system ids to search by
	 * @return Collection of Response objects matching search criteria
	 */
	public abstract Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);

	/**
	 * Finder for responses in the ResponseStore
	 * 
	 * @param detectionSystemId Detection system id to search by
	 * @param earliest long representing timestamp of time to start search with
	 * @return Collection of Response objects matching search criteria
	 */
	public abstract Collection<Response> findResponses(String detectionSystemId, long earliest);

}
