package org.owasp.appsensor.analysis;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Threshold;
import org.owasp.appsensor.event.StatisticalEvent;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.util.DateUtils;

/**
 * This is a statistical {@link Event} analysis engine, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link org.owasp.appsensor.event.StatisticalEvent}
 * implementations. 
 * 
 * The implementation performs a simple analysis that watches the configured {@link Threshold} and 
 * determines if it has been crossed. If so, an {@link Attack} is created and added to the 
 * {@link org.owasp.appsensor.storage.AttackStore}. 
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceStatisticalEventAnalysisEngine implements AnalysisEngine {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceStatisticalEventAnalysisEngine.class);
	
	/**
	 * This method analyzes statistical {@link Event}s that are added to the system and 
	 * detects if the configured {@link Threshold} has been crossed. If so, an {@link Attack} is 
	 * created and added to the system.
	 * 
	 * @param observable object that was being obeserved - ignored in this case
	 * @param observedObject object that was added to observable. In this case
	 * 			we are only interested if the object is 
	 * 			a {@link org.owasp.appsensor.event.StatisticalEvent} object
	 */
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof StatisticalEvent) {
			StatisticalEvent event = (StatisticalEvent)observedObject;
			
			Collection<Event> existingEvents = 
					AppSensorServer.getInstance().getEventStore().findEvents(
							event.getUser(), 
							event.getDetectionPoint(),
							AppSensorServer.getInstance().getConfiguration().getRelatedDetectionSystems(event.getDetectionSystemId())
							);
			
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
	}
	
	/**
	 * Count the number of events over a time interval.
	 * 
	 * @param intervalInMillis interval as measured in milliseconds
	 * @param existingEvents set of events matching triggering event id/user pulled from event storage
	 * @return number of events matching time interval
	 */
	protected int countEvents(long intervalInMillis, Collection<Event> existingEvents, Event triggeringEvent) {
		int count = 0;
		
		//grab the startTime to begin counting from based on the current time - interval
		long startTime = DateUtils.getCurrentTime() - intervalInMillis;
		
		//count events after most recent attack.
		long mostRecentAttackTime = findMostRecentAttackTime(triggeringEvent);
		
		for (Event event : existingEvents) {
			if (event instanceof StatisticalEvent) {
				
				//ensure only events that have occurred since the last attack are considered
				if (event.getTimestamp() > mostRecentAttackTime) {
					if (intervalInMillis > 0) {
						if (event.getTimestamp() > startTime) {
							//only increment when event occurs within specified interval
							count++;
						}
					} else {
						//no interval - all events considered
						count++;
					}
				}
			}
		}
		
		return count;
	}
	
	/**
	 * Find most recent attack matching the given event (user, detection point, detection system)
	 * and find it's timestamp. 
	 * 
	 * Event should only be counted if they've occurred after the most recent attack.
	 * 
	 * @param event event to use to find matching attacks
	 * @return timestamp representing last matching attack, or -1L if not found
	 */
	protected long findMostRecentAttackTime(Event event) {
		long newest = -1L;
		
		Collection<Attack> attacks = AppSensorServer.getInstance().getAttackStore().findAttacks(
				event.getUser(), 
				event.getDetectionPoint(), 
				AppSensorServer.getInstance().getConfiguration().getRelatedDetectionSystems(event.getDetectionSystemId()));

		for (Attack attack : attacks) {
			if (attack.getTimestamp() > newest) {
				newest = attack.getTimestamp();
			}
		}
		
		return newest;
	}
	
}
