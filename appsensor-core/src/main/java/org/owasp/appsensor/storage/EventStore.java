package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.Event;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.EventListener;

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
public abstract class EventStore { //extends Observable {

	private static Collection<EventListener> listeners = new CopyOnWriteArrayList<>();
	
	/**
	 * Add an {@link org.owasp.appsensor.Event} to the EventStore
	 * 
	 * @param event the {@link org.owasp.appsensor.Event} to add to the EventStore
	 */
	public abstract void addEvent(Event event);
	
	/**
	 * A finder for Event objects in the EventStore
	 * 
	 * @param criteria the {@link org.owasp.appsensor.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Event} objects matching the search criteria.
	 */
	public abstract Collection<Event> findEvents(SearchCriteria criteria);

	public void registerListener(EventListener listener) {
		if (! listeners.contains(listener)) {
			listeners.add(listener);
		}
	}
	
	public void notifyListeners(Event event) {
		for (EventListener listener : listeners) {
			listener.onAdd(event);
		}
	}
}
