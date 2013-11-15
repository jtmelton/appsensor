package org.owasp.appsensor.analysis.impl;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.AnalysisEngine;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.util.DateUtils;

public class ReferenceEventAnalysisEngine implements AnalysisEngine {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(ReferenceEventAnalysisEngine.class);
	
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Event) {
			Event event = (Event)observedObject;
			
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

			int thresholdCount = event.getDetectionPoint().getThreshold().getCount();
			
			if (eventCount % thresholdCount == 0) {
				logger.info("Violation Observed for user <" + event.getUser().getUsername() + "> - storing attack");
				//have determined this event triggers attack
				ServerObjectFactory.getAttackStore().addAttack(new Attack(event));
			}
		} 
	}
	
	protected int countEvents(Event currentEvent, Collection<Event> existingEvents) {
		int count = 0;
		
		long intervalInMillis = currentEvent.getDetectionPoint().getThreshold().getInterval().toMillis();
		
		long startTime = DateUtils.getCurrentTime() - intervalInMillis;
		
		for (Event event : existingEvents) {
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
		
		return count;
	}
	
}
