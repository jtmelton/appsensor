package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.Observable;
import java.util.Observer;

import javax.inject.Inject;

import org.owasp.appsensor.Event;
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
public abstract class EventStore extends Observable {
	
	/**
	 * Add an {@link org.owasp.appsensor.Event} to the EventStore
	 * 
	 * @param event the {@link org.owasp.appsensor.Event} to add to the EventStore
	 */
	public abstract void addEvent(Event event);
	
	public abstract Collection<Event> findEvents(SearchCriteria criteria);
	
	@Inject @EventStoreObserver
	public void setObservers(Collection<Observer> observers) {
		for (Observer observer : observers) {
			super.addObserver(observer);	
		}
	}
	
//	/**
//	 * A finder for Event objects in the EventStore
//	 * 
//	 * @param user the {@link org.owasp.appsensor.User} object to search by
//	 * @param detectionPoint The {@link org.owasp.appsensor.DetectionPoint} to search by
//	 * @param detectionSystemIds A {@link java.util.Collection} of detection system ids to search by
//	 * @param earliest long representing timestamp of time to start search with
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Event} objects matching the search criteria.
//	 */
//	public abstract Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds, Long earliest);
//	
//	/**
//	 * A finder for Event objects in the EventStore
//	 * 
//	 * @param user the {@link org.owasp.appsensor.User} object to search by
//	 * @param detectionPoint The {@link org.owasp.appsensor.DetectionPoint} to search by
//	 * @param detectionSystemIds A {@link java.util.Collection} of detection system ids to search by
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Event} objects matching the search criteria.
//	 */
//	public abstract Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
//	
//	/**
//	 * A finder for Event objects in the EventStore
//	 * 
//	 * @param detectionSystemId Detection system id to search by
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Event} objects matching the search criteria.
//	 */
//	public abstract Collection<Event> findEvents(String detectionSystemId, Long earliest);
//	
//	/**
//	 * A finder for Event objects in the EventStore
//	 * 
//	 * @param earliest long representing timestamp of time to start search with
//	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Event} objects matching the search criteria.
//	 */
//	public abstract Collection<Event> findEvents(Long earliest);

}
