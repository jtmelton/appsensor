package org.owasp.appsensor.event.impl;

import java.util.Collection;
import java.util.Collections;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.EventManager;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.AppSensorServer;

/**
 * Local event manager that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
public class LocalEventManager implements EventManager {

	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(LocalEventManager.class);
	
	@Override
	public void addEvent(Event event) {
		AppSensorServer.getInstance().getEventStore().addEvent(event);
	}
	
	public void addAttack(Attack attack) {
		AppSensorServer.getInstance().getAttackStore().addAttack(attack);
	}
	
	@Override
	public Collection<Response> getResponses() {
		logger.info("The local event manager executes responses immediately " +
				"and therefore does not support retrieving responses");
		
		return Collections.emptyList();
	}

}
