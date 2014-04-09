package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.configuration.Configurable;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.ResponseListener;

/**
 * A store is an observable object. 
 * 
 * It is watched by implementations of the {@link ResponseListener} interfaces. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public abstract class ResponseStore implements Configurable {
	
	private static Collection<ResponseListener> listeners = new CopyOnWriteArrayList<>();
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
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

	/**
	 * Register an {@link ResponseListener} to notify when {@link Response}s are added
	 * 
	 * @param listener the {@link ResponseListener} to register
	 */
	public void registerListener(ResponseListener listener) {
		if (! listeners.contains(listener)) {
			listeners.add(listener);
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
