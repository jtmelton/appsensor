package org.owasp.appsensor.event;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.joda.time.DateTime;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.handler.LocalRequestHandler;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.util.DateUtils;
import org.slf4j.Logger;

/**
 * Local {@link EventManager} that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
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
