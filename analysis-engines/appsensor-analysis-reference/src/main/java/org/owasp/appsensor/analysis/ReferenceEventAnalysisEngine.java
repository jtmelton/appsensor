package org.owasp.appsensor.analysis;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

/**
 * This is a statistical {@link Event} analysis engine, 
 * and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link Event} class.
 * 
 * The implementation performs a simple analysis that watches the configured {@link Threshold} and 
 * determines if it has been crossed. If so, an {@link Attack} is created and added to the 
 * {@link AttackStore}. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class ReferenceEventAnalysisEngine extends EventAnalysisEngine {

	private Logger logger;
	
	@Inject
	private AppSensorServer appSensorServer;
	
	/**
	 * This method analyzes statistical {@link Event}s that are added to the system and 
	 * detects if the configured {@link Threshold} has been crossed. If so, an {@link Attack} is 
	 * created and added to the system.
	 * 
	 * @param event the {@link Event} that was added to the {@link EventStore}
	 */
	@Override
	public void analyze(Event event) {
		
		SearchCriteria criteria = new SearchCriteria().
				setUser(event.getUser()).
				setDetectionPoint(event.getDetectionPoint()).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystem()));

		// find all events matching this event for this user 
		Collection<Event> existingEvents = appSensorServer.getEventStore().findEvents(criteria);

		Collection<DetectionPoint> configuredDetectionPoints = appSensorServer.getConfiguration().findDetectionPoints(event.getDetectionPoint());

		if (configuredDetectionPoints.size() > 0) {
			
			for(DetectionPoint configuredDetectionPoint : configuredDetectionPoints) {
				
				// filter and count events that match this detection point (filtering by threshold) 
				// and that are after the most recent attack (filter by timestamp)
				int eventCount = countEvents(existingEvents, event, configuredDetectionPoint);
				
				// if the event count is 0, reset to 1 -> we know at least 1 event has occurred (the one we're considering)
				// this can occur sometimes when testing with dates out of the given range or due to clock drift
				if (eventCount == 0) {
					eventCount = 1;
				}
				
				// examples for the below code
				// 1. count is 5, t.count is 10 (5%10 = 5, No Violation)
				// 2. count is 45, t.count is 10 (45%10 = 5, No Violation) 
				// 3. count is 10, t.count is 10 (10%10 = 0, Violation Observed)
				// 4. count is 30, t.count is 10 (30%10 = 0, Violation Observed)
		
				int thresholdCount = configuredDetectionPoint.getThreshold().getCount();
		
				if (eventCount % thresholdCount == 0) {
					logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> - storing attack");
					
					//have determined this event triggers attack
					//ensure appropriate detection point is being used (associated responses, etc.)
					Attack attack = new Attack(
							event.getUser(),
							configuredDetectionPoint,
							event.getTimestamp(),
							event.getDetectionSystem(),
							event.getResource()
							);
					
					appSensorServer.getAttackStore().addAttack(attack);
				}
			}
		} else {
			logger.error("Could not find detection point configured for this type: " + event.getDetectionPoint().getLabel());
		}
	}
	
	/**
	 * Count the number of {@link Event}s over a time {@link Interval} specified in milliseconds.
	 * 
	 * @param existingEvents set of {@link Event}s matching triggering {@link Event} id/user pulled from {@link Event} storage
	 * @param triggeringEvent the {@link Event} that triggered analysis
	 * @param configuredDetectionPoint the {@link DetectionPoint} we are currently considering
	 * @return number of {@link Event}s matching time {@link Interval} and configured {@link DetectionPoint}
	 */
	protected int countEvents(Collection<Event> existingEvents, Event triggeringEvent, DetectionPoint configuredDetectionPoint) {
		int count = 0;
		
		long intervalInMillis = configuredDetectionPoint.getThreshold().getInterval().toMillis();
		
		//grab the startTime to begin counting from based on the current time - interval
		DateTime startTime = DateUtils.getCurrentTimestamp().minusMillis((int)intervalInMillis);
		
		//count events after most recent attack.
		DateTime mostRecentAttackTime = findMostRecentAttackTime(triggeringEvent, configuredDetectionPoint);
		
		for (Event event : existingEvents) {
			DateTime eventTimestamp = DateUtils.fromString(event.getTimestamp());
			//ensure only events that have occurred since the last attack are considered
			if (eventTimestamp.isAfter(mostRecentAttackTime)) {
				if (intervalInMillis > 0) {
					if (DateUtils.fromString(event.getTimestamp()).isAfter(startTime)) {
						//only increment when event occurs within specified interval
						count++;
					}
				} else {
					//no interval - all events considered
					count++;
				}
			}
		}
		
		return count;
	}
	
	/**
	 * Find most recent {@link Attack} matching the given {@link Event} {@link User}, {@link DetectionPoint} 
	 * matching the currently configured detection point (supporting multiple detection points per label), 
	 * detection system and find it's timestamp. 
	 * 
	 * The {@link Event} should only be counted if they've occurred after the most recent {@link Attack}.
	 * 
	 * @param event {@link Event} to use to find matching {@link Attack}s
	 * @param configuredDetectionPoint {@link DetectionPoint} to use to find matching {@link Attack}s
	 * @return timestamp representing last matching {@link Attack}, or -1L if not found
	 */
	protected DateTime findMostRecentAttackTime(Event event, DetectionPoint configuredDetectionPoint) {
		DateTime newest = DateUtils.epoch();
		
		SearchCriteria criteria = new SearchCriteria().
				setUser(event.getUser()).
				setDetectionPoint(configuredDetectionPoint).
				setDetectionSystemIds(appSensorServer.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystem()));
		
		Collection<Attack> attacks = appSensorServer.getAttackStore().findAttacks(criteria);
		
		for (Attack attack : attacks) {
			if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
				newest = DateUtils.fromString(attack.getTimestamp());
			}
		}
		
		return newest;
	}
	
}
