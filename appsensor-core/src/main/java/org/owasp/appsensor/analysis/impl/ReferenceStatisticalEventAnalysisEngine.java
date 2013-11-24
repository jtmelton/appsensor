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
			
			int eventCount = countEvents(event, existingEvents);
			
			//4 examples for the below code
			//1. count is 5, t.count is 10 (5%10 = 5, No Violation)
			//2. count is 45, t.count is 10 (45%10 = 5, No Violation) 
			//3. count is 10, t.count is 10 (10%10 = 0, Violation Observed)
			//4. count is 30, t.count is 10 (30%10 = 0, Violation Observed)

			int thresholdCount = findConfiguredDetectionPoint(event.getDetectionPoint()).getThreshold().getCount();
			
			if (eventCount % thresholdCount == 0) {
				logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> - storing attack");
				//have determined this event triggers attack
				ServerObjectFactory.getAttackStore().addAttack(new Attack(event));
			}
		} 
	}
	
	protected int countEvents(Event currentEvent, Collection<Event> existingEvents) {
		int count = 0;
		
		long intervalInMillis = findConfiguredDetectionPoint(currentEvent.getDetectionPoint()).getThreshold().getInterval().toMillis();
		
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
	
	protected DetectionPoint findConfiguredDetectionPoint(DetectionPoint triggeringDetectionPoint) {
		DetectionPoint detectionPoint = null;
		
		for (DetectionPoint configuredDetectionPoint : ServerObjectFactory.getConfiguration().getDetectionPoints()) {
			if (configuredDetectionPoint.getId().equals(triggeringDetectionPoint.getId())) {
				detectionPoint = configuredDetectionPoint;
				break;
			}
		}
		
		return detectionPoint;
	}
	
}
