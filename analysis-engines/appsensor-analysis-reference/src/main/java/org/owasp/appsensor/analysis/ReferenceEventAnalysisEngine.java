package org.owasp.appsensor.analysis;

import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Interval;
import org.owasp.appsensor.Threshold;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.EventListener;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.storage.AttackStore;
import org.owasp.appsensor.storage.EventStore;
import org.owasp.appsensor.util.DateUtils;

/**
 * This is a statistical {@link Event} analysis engine, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link StatisticalEvent}
 * implementations. 
 * 
 * The implementation performs a simple analysis that watches the configured {@link Threshold} and 
 * determines if it has been crossed. If so, an {@link Attack} is created and added to the 
 * {@link AttackStore}. 
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceEventAnalysisEngine implements AnalysisEngine, EventListener {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceEventAnalysisEngine.class);
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
	/**
	 * This method analyzes statistical {@link Event}s that are added to the system and 
	 * detects if the configured {@link Threshold} has been crossed. If so, an {@link Attack} is 
	 * created and added to the system.
	 * 
	 * @param event the {@link Event} that was added to the {@link EventStore}
	 */
	@Override
	public void onAdd(Event event) {
		SearchCriteria criteria = new SearchCriteria().
				setUser(event.getUser()).
				setDetectionPoint(event.getDetectionPoint()).
				setDetectionSystemIds(AppSensorServer.getInstance().getConfiguration().getRelatedDetectionSystems(event.getDetectionSystemId()));

		Collection<Event> existingEvents = AppSensorServer.getInstance().getEventStore().findEvents(criteria);

		DetectionPoint configuredDetectionPoint = AppSensorServer.getInstance().getConfiguration().findDetectionPoint(event.getDetectionPoint());
		
		int eventCount = countEvents(configuredDetectionPoint.getThreshold().getInterval().toMillis(), existingEvents, event);

		//4 examples for the below code
		//1. count is 5, t.count is 10 (5%10 = 5, No Violation)
		//2. count is 45, t.count is 10 (45%10 = 5, No Violation) 
		//3. count is 10, t.count is 10 (10%10 = 0, Violation Observed)
		//4. count is 30, t.count is 10 (30%10 = 0, Violation Observed)

		int thresholdCount = configuredDetectionPoint.getThreshold().getCount();

		if (eventCount % thresholdCount == 0) {
			logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> - storing attack");
			//have determined this event triggers attack
			AppSensorServer.getInstance().getAttackStore().addAttack(new Attack(event));
		}
	}
	
	/**
	 * Count the number of {@link Event}s over a time {@link Interval} specified in milliseconds.
	 * 
	 * @param intervalInMillis {@link Interval} as measured in milliseconds
	 * @param existingEvents set of {@link Event}s matching triggering {@link Event} id/user pulled from {@link Event} storage
	 * @return number of {@link Event}s matching time {@link Interval}
	 */
	protected int countEvents(long intervalInMillis, Collection<Event> existingEvents, Event triggeringEvent) {
		int count = 0;
		
		//grab the startTime to begin counting from based on the current time - interval
		DateTime startTime = DateUtils.getCurrentTimestamp().minusMillis((int)intervalInMillis);
		
		//count events after most recent attack.
		DateTime mostRecentAttackTime = findMostRecentAttackTime(triggeringEvent);
		
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
	 * Find most recent {@link Attack} matching the given {@link Event} ({@link User}, {@link DetectionPoint}, detection system)
	 * and find it's timestamp. 
	 * 
	 * The {@link Event} should only be counted if they've occurred after the most recent {@link Attack}.
	 * 
	 * @param event {@link Event} to use to find matching {@link Attack}s
	 * @return timestamp representing last matching {@link Attack}, or -1L if not found
	 */
	protected DateTime findMostRecentAttackTime(Event event) {
		DateTime newest = DateUtils.epoch();
		
		SearchCriteria criteria = new SearchCriteria().
				setUser(event.getUser()).
				setDetectionPoint(event.getDetectionPoint()).
				setDetectionSystemIds(AppSensorServer.getInstance().getConfiguration().getRelatedDetectionSystems(event.getDetectionSystemId()));
		
		Collection<Attack> attacks = AppSensorServer.getInstance().getAttackStore().findAttacks(criteria);
		
		for (Attack attack : attacks) {
			if (DateUtils.fromString(attack.getTimestamp()).isAfter(newest)) {
				newest = DateUtils.fromString(attack.getTimestamp());
			}
		}
		
		return newest;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
