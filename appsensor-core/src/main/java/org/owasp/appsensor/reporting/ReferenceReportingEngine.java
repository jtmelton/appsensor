package org.owasp.appsensor.reporting;

import java.util.Observable;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.logging.Logger;

public class ReferenceReportingEngine implements ReportingEngine {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(ReferenceReportingEngine.class);
	
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Event) {
			Event event = (Event)observedObject;
			
			logger.info("Reporter observed event by user [" + event.getUser().getUsername() + "]");
		} else if (observedObject instanceof Attack) {
			Attack attack = (Attack)observedObject;

			logger.info("Reporter observed attack by user [" + attack.getUser().getUsername() + "]");
		} else if (observedObject instanceof Response) {
			Response response = (Response)observedObject;

			logger.info("Reporter observed response for user [" + response.getUser().getUsername() + "]");
		}
	}
}
