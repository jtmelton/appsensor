package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.ResponseListener;

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
public abstract class ResponseStore { //extends Observable {
	
	private static Collection<ResponseListener> listeners = new CopyOnWriteArrayList<>();
	
	/**
	 * Add a response to the ResponseStore
	 * 
	 * @param response {@link org.owasp.appsensor.Response} to add to the ResponseStore
	 */
	public abstract void addResponse(Response response);
	
	/**
	 * Finder for responses in the ResponseStore
	 * 
	 * @param criteria the {@link org.owasp.appsensor.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Response} objects matching the search criteria.
	 */
	public abstract Collection<Response> findResponses(SearchCriteria criteria);

	public void registerListener(ResponseListener listener) {
		if (! listeners.contains(listener)) {
			listeners.add(listener);
		}
	}
	
	public void notifyListeners(Response response) {
		for (ResponseListener listener : listeners) {
			listener.onAdd(response);
		}
	}
}
