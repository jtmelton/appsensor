package org.owasp.appsensor.core.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Inject;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.ResponseListener;
import org.owasp.appsensor.core.util.DateUtils;

/**
 * A store is an observable object. 
 * 
 * It is watched by implementations of the {@link ResponseListener} interfaces. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
public abstract class ResponseStore {
	
	private static Collection<ResponseListener> listeners = new CopyOnWriteArrayList<>();
	
	/**
	 * Add a response to the ResponseStore
	 * 
	 * @param response {@link org.owasp.appsensor.core.Response} to add to the ResponseStore
	 */
	public abstract void addResponse(Response response);
	

	/**
	 * Finder for responses in the ResponseStore
	 * 
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Response} objects matching the search criteria.
	 */
	public abstract Collection<Response> findResponses(SearchCriteria criteria);
	
	/**
	 * Finder for responses in the ResponseStore
	 * 
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Response} objects matching the search criteria.
	 */
	public Collection<Response> findResponses(SearchCriteria criteria, Collection<Response> responses) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Response> matches = new ArrayList<Response>();
		
		User user = criteria.getUser();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		for (Response response : responses) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(response.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(response.getDetectionSystem().getDetectionSystemId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(response.getTimestamp())) : true;
					
			if (userMatch && detectionSystemMatch && earliestMatch) {
				matches.add(response);
			}
		}
		
		return matches;
	}

	/**
	 * Register an {@link ResponseListener} to notify when {@link Response}s are added
	 * 
	 * @param listener the {@link ResponseListener} to register
	 */
	public void registerListener(ResponseListener listener) {
		if (! listeners.contains(listener)) {
			boolean unique = true;
			
			for (ResponseListener existing : listeners) {
				if (existing.getClass().equals(listener.getClass())) {
					unique = false;
					break;
				}
			}
			
			if (unique) {
				listeners.add(listener);
			}
		}
	}
	
	/**
	 * Notify each {@link ResponseListener} of the specified {@link Response}
	 * 
	 * @param response the {@link Response} to notify each {@link ResponseListener} about
	 */
	public void notifyListeners(Response response) {
		for (ResponseListener listener : listeners) {
			listener.onAdd(response);
		}
	}
	
	/**
	 * Automatically inject any {@link ResponseStoreListener}s, which are implementations of 
	 * {@link ResponseListener} so they can be notified of changes.
	 * 
	 * @param collection of {@link ResponseListener}s that are injected to be 
	 * 			listeners on the {@link ResponseStore}
	 */
	@Inject @ResponseStoreListener
	public void setListeners(Collection<ResponseListener> listeners) {
		for (ResponseListener listener : listeners) {
			registerListener(listener);	
		}
	}

}
