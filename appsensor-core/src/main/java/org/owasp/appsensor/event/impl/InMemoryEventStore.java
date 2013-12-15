package org.owasp.appsensor.event.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.EventStore;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.User;

/**
 * This is a reference implementation of the event store, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link org.owasp.appsensor.Event} implementations. 
 * 
 * The implementation is trivial and simply stores the Event in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryEventStore extends EventStore {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryEventStore.class);
	
	private Collection<Event> events = new CopyOnWriteArrayList<Event>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		logger.warning("Security event " + event.getDetectionPoint().getId() + " triggered by user: " + event.getUser().getUsername());
		
		events.add(event);
		
		super.setChanged();
		
		super.notifyObservers(event);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(User user, DetectionPoint search, Collection<String> detectionSystemIds) {
		Collection<Event> matchingEvents = new ArrayList<Event>();
		
		for (Event event : events) {
			if (user.equals(event.getUser()) && 
					detectionSystemIds.contains(event.getDetectionSystemId()) &&
					event.getDetectionPoint().getId().equals(search.getId())) {
				matchingEvents.add(event);
			}
		}
		
		return matchingEvents;
	}

}
