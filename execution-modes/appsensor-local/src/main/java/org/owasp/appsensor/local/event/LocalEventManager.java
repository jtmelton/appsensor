package org.owasp.appsensor.local.event;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.event.EventManager;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.util.DateUtils;
import org.owasp.appsensor.local.handler.LocalRequestHandler;
import org.slf4j.Logger;

/**
 * Local {@link EventManager} that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class LocalEventManager implements EventManager {
	
	@SuppressWarnings("unused")
	private Logger logger;
	
	@Inject
	private LocalRequestHandler requestHandler;
	
	private DateTime responsesLastChecked = DateUtils.getCurrentTimestamp();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addEvent(Event event) {
		requestHandler.addEvent(event);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		requestHandler.addAttack(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> getResponses() {
		Collection<Response> responses = requestHandler.getResponses(responsesLastChecked.toString());
		
		//now update last checked
		responsesLastChecked = DateUtils.getCurrentTimestamp();
		
		return responses;
	}
	
}
