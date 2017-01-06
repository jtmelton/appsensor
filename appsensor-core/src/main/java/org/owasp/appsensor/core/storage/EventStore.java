package org.owasp.appsensor.core.storage;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Inject;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.rule.MonitorPoint;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.core.util.DateUtils;

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
	 * Automatically inject any {@link EventStoreListener}s, which are implementations of
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

	/**
	 * A finder for Event objects in the EventStore
	 *
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @param events the {@link Event} objects to match on - supplied by subclasses
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.core.Event} objects matching the search criteria.
	 */
	public Collection<Event> findEvents(SearchCriteria criteria, Collection<Event> events) {
		if (criteria == null) {
			throw new IllegalArgumentException("criteria must be non-null");
		}

		Collection<Event> matches = new ArrayList<Event>();

		for (Event event : events) {
			if (isMatchingEvent(criteria, event)) {
				matches.add(event);
			}
		}

		return matches;
	}

	/**
	 * A finder for Event objects in the EventStore
	 *
	 * @param criteria the {@link org.owasp.appsensor.core.criteria.SearchCriteria} object to search by
	 * @param event the {@link Event} object to match on
	 * @return true or false depending on the matching of the search criteria to the event
	 */
	protected boolean isMatchingEvent(SearchCriteria criteria, Event event) {
		boolean match = false;

		User user = criteria.getUser();
		DetectionPoint detectionPoint = criteria.getDetectionPoint();
		Rule rule = criteria.getRule();
		Collection<String> detectionSystemIds = criteria.getDetectionSystemIds();
		DateTime earliest = DateUtils.fromString(criteria.getEarliest());

		// check user match if user specified
		boolean userMatch = (user != null) ? user.equals(event.getUser()) : true;

		// check detection system match if detection systems specified
		boolean detectionSystemMatch = (detectionSystemIds != null && detectionSystemIds.size() > 0) ?
				detectionSystemIds.contains(event.getDetectionSystem().getDetectionSystemId()) : true;

		// check detection point match if detection point specified
		boolean detectionPointMatch = (detectionPoint != null) ?
				detectionPoint.typeAndThresholdMatches(event.getDetectionPoint()) : true;

		// check rule match if rule specified
		boolean ruleMatch = (rule != null) ?
				rule.typeAndThresholdContainsDetectionPoint(event.getDetectionPoint()) : true;

		DateTime eventTimestamp = DateUtils.fromString(event.getTimestamp());

		boolean earliestMatch = (earliest != null) ?
				(earliest.isBefore(eventTimestamp) || earliest.isEqual(eventTimestamp))
				: true;

		if (userMatch && detectionSystemMatch && detectionPointMatch && ruleMatch && earliestMatch) {
			match = true;
		}

		return match;
	}

}
