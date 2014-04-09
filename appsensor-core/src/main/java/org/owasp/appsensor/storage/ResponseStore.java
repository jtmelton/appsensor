package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.Observable;
import java.util.Observer;

import javax.inject.Inject;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.criteria.SearchCriteria;

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
	 * @param response {@link org.owasp.appsensor.Response} to add to the ResponseStore
	 */
	public abstract void addResponse(Response response);
	
	public abstract Collection<Response> findResponses(SearchCriteria criteria);
	
	@Inject @ResponseStoreObserver
	public void setObservers(Collection<Observer> observers) {
		for (Observer observer : observers) {
			super.addObserver(observer);	
		}
	}
	
//	/**
//	 * Finder for responses in the ResponseStore
//	 * 
//	 * * @param user the {@link org.owasp.appsensor.User} object to search by
//	 * @param detectionPoint The {@link org.owasp.appsensor.DetectionPoint} to search by
//	 * @param detectionSystemIds A {@link java.util.Collection} of detection system ids to search by
//	 * @param earliest long representing timestamp of time to start search with
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Response} objects matching the search criteria.
//	 */
//	public abstract Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds, Long earliest);
//
//	/**
//	 * Finder for responses in the ResponseStore
//	 * 
//	 * * @param user the {@link org.owasp.appsensor.User} object to search by
//	 * @param detectionPoint The {@link org.owasp.appsensor.DetectionPoint} to search by
//	 * @param detectionSystemIds A {@link java.util.Collection} of detection system ids to search by
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Response} objects matching the search criteria.
//	 */
//	public abstract Collection<Response> findResponses(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
//	
//	/**
//	 * Finder for responses in the ResponseStore
//	 * 
//	 * @param detectionSystemId Detection system id to search by
//	 * @param earliest long representing timestamp of time to start search with
//	 * @return Collection of {@link org.owasp.appsensor.Response} objects matching search criteria
//	 */
//	public abstract Collection<Response> findResponses(String detectionSystemId, Long earliest);
//	
//	/**
//	 * Finder for responses in the ResponseStore
//	 * 
//	 * @param earliest long representing timestamp of time to start search with
//	 * @return Collection of {@link org.owasp.appsensor.Response} objects matching search criteria
//	 */
//	public abstract Collection<Response> findResponses(Long earliest);

}
