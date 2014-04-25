package org.owasp.appsensor.reporting;

import java.util.Collection;

import javax.inject.Named;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.logging.Logger;
import org.owasp.appsensor.storage.AttackStoreListener;
import org.owasp.appsensor.storage.EventStoreListener;
import org.owasp.appsensor.storage.ResponseStoreListener;

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
@Named
@EventStoreListener
@AttackStoreListener
@ResponseStoreListener
@Loggable
public class SimpleLoggingReportingEngine implements ReportingEngine {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(SimpleLoggingReportingEngine.class);
	
	private ExtendedConfiguration extendedConfiguration = new ExtendedConfiguration();
	
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
	public ExtendedConfiguration getExtendedConfiguration() {
		return extendedConfiguration;
	}
	
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration) {
		this.extendedConfiguration = extendedConfiguration;
	}
	
}
