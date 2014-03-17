package org.owasp.appsensor.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.User;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.logging.Logger;

/**
 * This is a reference implementation of the {@link EventStore}, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link Event} implementations. 
 * 
 * The implementation is trivial and simply stores the {@link Event} in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryEventStore extends EventStore {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(InMemoryEventStore.class);
	
	/** maintain a collection of {@link Event}s as an in-memory list */
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
	public Collection<Event> findEvents(SearchCriteria criteria) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}
		
		Collection<Event> matches = new ArrayList<Event>();
		
		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds(); 
		Long earliest = criteria.getEarliest();
		
		for (Event event : events) {
			//check user match if user specified
			boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;
			
			//check detection system match if detection systems specified
			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
					detectionSystemIds.contains(event.getDetectionSystemId()) : true;
			
			//check detection point match if detection point specified
			boolean detectionPointMatch = (detectionPoint != null) ? 
					detectionPoint.getId().equals(event.getDetectionPoint().getId()) : true;
			
			boolean earliestMatch = (earliest != null) ? earliest.longValue() < event.getTimestamp() : true;
			
			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
				matches.add(event);
			}
		}
		
		return matches;
	}
	
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds, Long earliest) {
//		Collection<Event> matches = new ArrayList<Event>();
//		
//		for (Event event : events) {
//			//check user match if user specified
//			boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;
//			
//			//check detection system match if detection systems specified
//			boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ? 
//					detectionSystemIds.contains(event.getDetectionSystemId()) : true;
//			
//			//check detection point match if detection point specified
//			boolean detectionPointMatch = (detectionPoint != null) ? 
//					detectionPoint.getId().equals(event.getDetectionPoint().getId()) : true;
//			
//			boolean earliestMatch = (earliest != null) ? earliest.longValue() < event.getTimestamp() : true;
//			
//			if (userMatch && detectionSystemMatch && detectionPointMatch && earliestMatch) {
//				matches.add(event);
//			}
//		}
//		
//		return matches;
//	}
//
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Event> findEvents(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds) {
//		return findEvents(user, detectionPoint, detectionSystemIds, null);
//	}
//
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Event> findEvents(String detectionSystemId, Long earliest) {
//		Collection<String> detectionSystemIds = new ArrayList<String>();
//		detectionSystemIds.add(detectionSystemId);
//		
//		return findEvents(null, null, detectionSystemIds, earliest);
//	}
//
//	/**
//	 * {@inheritDoc}
//	 */
//	@Override
//	public Collection<Event> findEvents(Long earliest) {
//		return findEvents(null, null, null, earliest);
//	}

}
