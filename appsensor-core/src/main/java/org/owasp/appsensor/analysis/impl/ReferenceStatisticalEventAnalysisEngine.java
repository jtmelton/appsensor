package org.owasp.appsensor.analysis.impl;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.AnalysisEngine;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.StatisticalEvent;
import org.owasp.appsensor.util.DateUtils;

/**
 * This is a statistical event analysis engine, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are only concerned with {@link org.owasp.appsensor.StatisticalEvent}
 * implementations. 
 * 
 * The implementation performs a simple analysis that watches the configured threshold and 
 * determines if it has been crossed. If so, an attack is created and added to the 
 * {@link org.owasp.appsensor.AttackStore}. 
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceStatisticalEventAnalysisEngine implements AnalysisEngine {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(ReferenceStatisticalEventAnalysisEngine.class);
	
	/**
	 * This method analyzes statistical events that are added to the system and 
	 * detects if the configured threshold has been crossed. If so, an attack is 
	 * created and added to the system.
	 * 
	 * @param observable object that was being obeserved - ignored in this case
	 * @param observedObject object that was added to observable. In this case
	 * 			we are only interested if the object is 
	 * 			a {@link org.owasp.appsensor.StatisticalEvent} object
	 */
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof StatisticalEvent) {
			StatisticalEvent event = (StatisticalEvent)observedObject;
			
			Collection<Event> existingEvents = 
					ServerObjectFactory.getEventStore().findEvents(
							event.getUser(), 
							event.getDetectionPoint(),
							ServerObjectFactory.getConfiguration().getRelatedDetectionSystems(event.getDetectionSystemId())
							);
			
			DetectionPoint configuredDetectionPoint = ServerObjectFactory.getConfiguration().findDetectionPoint(event.getDetectionPoint());
			
			int eventCount = countEvents(configuredDetectionPoint.getThreshold().getInterval().toMillis(), existingEvents);
			
			//4 examples for the below code
			//1. count is 5, t.count is 10 (5%10 = 5, No Violation)
			//2. count is 45, t.count is 10 (45%10 = 5, No Violation) 
			//3. count is 10, t.count is 10 (10%10 = 0, Violation Observed)
			//4. count is 30, t.count is 10 (30%10 = 0, Violation Observed)

			int thresholdCount = configuredDetectionPoint.getThreshold().getCount();
			
			if (eventCount % thresholdCount == 0) {
				logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> - storing attack");
				//have determined this event triggers attack
				ServerObjectFactory.getAttackStore().addAttack(new Attack(event));
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
	protected int countEvents(long intervalInMillis, Collection<Event> existingEvents) {
		int count = 0;
		
		long startTime = DateUtils.getCurrentTime() - intervalInMillis;
		
		for (Event event : existingEvents) {
			if (event instanceof StatisticalEvent) {
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
		
		return count;
	}
	
}
