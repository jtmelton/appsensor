package org.owasp.appsensor.storage.jpa2;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.storage.jpa2.dao.EventRepository;
import org.slf4j.Logger;

/**
 * This is a jpa2 implementation of the {@link EventStore}.
 * 
 * Implementations of the {@link EventListener} interface can register with 
 * this class and be notified when new {@link Event}s are added to the data store 
 * 
 * The implementation stores the {@link Event} in a jpa2 driven DB.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class Jpa2EventStore extends EventStore {
	
	private Logger logger;
	
	/** maintain a repository to read/write {@link Event}s from */
	@Inject 
	EventRepository eventRepository;
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		logger.warn("Security event " + event.getDetectionPoint().getLabel() + " triggered by user: " + event.getUser().getUsername());
		
		eventRepository.save(event);
		
		super.notifyListeners(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(SearchCriteria criteria) {
		Collection<Event> eventsAllTimestamps = eventRepository.find(criteria);
		
		// timestamp stored as string not queryable in DB, all timestamps come back, still need to filter this subset		
		return findEvents(criteria, eventsAllTimestamps);
	}
	
}
