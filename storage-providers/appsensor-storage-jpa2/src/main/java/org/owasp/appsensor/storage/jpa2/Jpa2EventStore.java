package org.owasp.appsensor.storage.jpa2;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.EventListener;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.storage.EventStore;
import org.owasp.appsensor.storage.jpa2.dao.EventRepository;
import org.owasp.appsensor.util.DateUtils;
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
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Event> matches = new ArrayList<Event>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());
		
		for (Event event : eventRepository.findAll()) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(event.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getLabel().equals(event.getDetectionPoint().getLabel()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.isBefore(DateUtils.fromString(event.getTimestamp())) : true;
					
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(event);
			}
		}
		
		return matches;
	}
	
}
