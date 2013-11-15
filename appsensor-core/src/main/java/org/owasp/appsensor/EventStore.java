package org.owasp.appsensor;

import java.util.Collection;
import java.util.Observable;

public abstract class EventStore extends Observable {
	public abstract void addEvent(Event event);
	public abstract Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
}
