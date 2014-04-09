package org.owasp.appsensor.event;

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.handler.LocalRequestHandler;
import org.owasp.appsensor.util.DateUtils;

/**
 * Local {@link EventManager} that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
@Named
public class LocalEventManager implements EventManager {

	@Inject
	private LocalRequestHandler requestHandler;
	
	private long responsesLastChecked = DateUtils.getCurrentTime();
	
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
//		logger.info("The local event manager executes responses immediately " +
//				"and therefore does not support retrieving responses");
//		
//		return Collections.emptyList();
		
		Collection<Response> responses = requestHandler.getResponses(responsesLastChecked);
		
		//now update last checked
		responsesLastChecked = DateUtils.getCurrentTime();
		
		return responses;
	}

}
