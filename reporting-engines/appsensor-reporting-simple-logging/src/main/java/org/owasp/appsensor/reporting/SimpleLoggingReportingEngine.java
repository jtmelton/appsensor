package org.owasp.appsensor.reporting;

import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.reporting.ReportingEngine;
import org.owasp.appsensor.core.storage.AttackStoreListener;
import org.owasp.appsensor.core.storage.EventStoreListener;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.slf4j.Logger;

/**
 * This is the reference reporting engine, and is an implementation of the observer pattern. 
 * 
 * It is notified with implementations of the *Listener interfaces and is 
 * passed the observed objects. In this case, we are concerned with {@link Event},
 *  {@link Attack} and {@link Response} implementations. 
 * 
 * The implementation simply logs the action. Other implementations are expected to create 
 * some manner of visualization.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@EventStoreListener
@AttackStoreListener
@ResponseStoreListener
@Loggable
public class SimpleLoggingReportingEngine implements ReportingEngine {
	
	private Logger logger;
	
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
	public Collection<Event> findEvents(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Response> findResponses(String earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getServerConfigurationAsJson() throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyValuePair getBase64EncodedServerConfigurationFileContent() throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countEvents(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countAttacks(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int countResponses(String earliest) throws NotAuthorizedException {
		throw new UnsupportedOperationException("This method is not implemented for WebSocket reporting implementation");
	}
}
