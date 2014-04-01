package org.owasp.appsensor.reporting;

import java.util.Collection;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.logging.Logger;

/**
 * This is the reference reporting engine, and is an implementation of the observer pattern. 
 * 
 * It is notified with implementations of the *Listener interfaces and is 
 * passed the observed objects. In this case, we are concerned with, {@link Event},
 *  {@link Attack} and {@link Response}
 * implementations. 
 * 
 * The implementation simply logs the action. Other implementations are expected to create 
 * some manner of visualization.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class SimpleLoggingReportingEngine implements ReportingEngine {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(SimpleLoggingReportingEngine.class);
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		logger.info("Reporter observed event by user [" + event.getUser().getUsername() + "]");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) {
		logger.info("Reporter observed attack by user [" + attack.getUser().getUsername() + "]");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		logger.info("Reporter observed response for user [" + response.getUser().getUsername() + "]");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Event> findEvents(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}
	
}
