package org.owasp.appsensor.event.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.EventStore;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.User;

public class InMemoryEventStore extends EventStore {
	
	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(InMemoryEventStore.class);
	
	private Collection<Event> events = new CopyOnWriteArrayList<Event>();
	
	@Override
	public void addEvent(Event event) {
		logger.warning("Security event " + event.getDetectionPoint().getId() + " triggered by user: " + event.getUser().getUsername());
		
		events.add(event);
		
		super.setChanged();
		
		super.notifyObservers(event);
	}

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
