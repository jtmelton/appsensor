package org.owasp.appsensor.core.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Inject;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;

/**
 * A store is an observable object. 
 * 
 * It is watched by implementations of the {@link EventListener} interfaces. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
public abstract class EventStore {

	private static Collection<EventListener> listeners = new CopyOnWriteArrayList<>();
	
	/**
	 * Add an {@link org.owasp.appsensor.core.Event} to the EventStore
	 * 
	 * @param event the {@link org.owasp.appsensor.core.Event} to add to the EventStore
	 */
	public abstract void addEvent(Event event);
	
	/**
	 * A finder for Event objects in the EventStore
	 * 
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Event} objects matching the search criteria.
	 */
	public abstract Collection<Event> findEvents(SearchCriteria criteria);

	/**
	 * Register an {@link EventListener} to notify when {@link Event}s are added
	 * 
	 * @param listener the {@link EventListener} to register
	 */
	public void registerListener(EventListener listener) {
		if (! listeners.contains(listener)) {
			boolean unique = true;
			
			for (EventListener existing : listeners) {
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
	 * Notify each {@link EventListener} of the specified {@link Event}
	 * 
	 * @param response the {@link Event} to notify each {@link EventListener} about
	 */
	public void notifyListeners(Event event) {
		for (EventListener listener : listeners) {
			listener.onAdd(event);
		}
	}
	
	/**
	 * Automatically inject any {@link @EventStoreListener}s, which are implementations of 
	 * {@link EventListener} so they can be notified of changes.
	 * 
	 * @param collection of {@link EventListener}s that are injected to be 
	 * 			listeners on the {@link @EventStore}
	 */
	@Inject @EventStoreListener
	public void setListeners(Collection<EventListener> listeners) {
		for (EventListener listener : listeners) {
			registerListener(listener);	
		}
	}
	
}
