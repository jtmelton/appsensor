package org.owasp.appsensor;

import java.util.Collection;
import java.util.Observable;

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
	 * Add an Event to the EventStore
	 * 
	 * @param event the Event to add to the EventStore
	 */
	public abstract void addEvent(Event event);
	
	/**
	 * A finder for Event objects in the EventStore
	 * 
	 * @param user the User object to search by
	 * @param detectionPoint The DetectionPoint object to search by
	 * @param detectionSystemIds A Collection of detection system ids to search by
	 * @return A Collection of Event objects matching the search criteria
	 */
	public abstract Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);

}
