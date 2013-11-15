package org.owasp.appsensor.event.impl;

import java.util.Collection;
import java.util.Collections;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.EventManager;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;

/**
 * Local event manager that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author jtmelton
 *
 */
public class LocalEventManager implements EventManager {

	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(LocalEventManager.class);
	
	@Override
	public void addEvent(Event event) {
		ServerObjectFactory.getEventStore().addEvent(event);
	}
	
	public void addAttack(Attack attack) {
		ServerObjectFactory.getAttackStore().addAttack(attack);
	}
	
	@Override
	public Collection<Response> getResponses() {
		logger.info("The local event manager executes responses immediately " +
				"and therefore does not support retrieving responses");
		
		return Collections.emptyList();
	}

}
