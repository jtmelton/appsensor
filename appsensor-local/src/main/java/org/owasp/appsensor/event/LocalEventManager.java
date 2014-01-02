package org.owasp.appsensor.event;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.handler.LocalRequestHandler;
import org.owasp.appsensor.util.DateUtils;

/**
 * Local event manager that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
public class LocalEventManager implements EventManager {

	private static LocalRequestHandler requestHandler = new LocalRequestHandler();
	
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
