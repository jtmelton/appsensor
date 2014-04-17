package org.owasp.appsensor.event;

import java.util.Collection;

import org.joda.time.DateTime;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.handler.LocalRequestHandler;
import org.owasp.appsensor.util.DateUtils;

/**
 * Local {@link EventManager} that is used when the application is configured
 * to run within the same JVM as the Analysis Engine.  
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 *
 */
public class LocalEventManager implements EventManager {

	private static LocalRequestHandler requestHandler = new LocalRequestHandler();
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
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

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
