package org.owasp.appsensor.reporting;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.logging.Logger;

/**
 * This is the reference reporting engine, and is an implementation of the Observer pattern. 
 * 
 * It is notified with implementations of the {@link java.util.Observable} interface and is 
 * passed the observed object. In this case, we are concerned with, {@link Event},
 *  {@link Attack} and {@link Response}
 * implementations. 
 * 
 * The implementation simply logs the action. Other implementations are expected to create 
 * some manner of visualization.
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class SimpleLoggingReportingEngine implements ReportingEngine {
	
	private static Logger logger = AppSensorServer.getInstance().getLogger().setLoggerClass(SimpleLoggingReportingEngine.class);
	
	/**
	 * This method reports on {@link Event}, {@link Attack} and {@link Response} objects 
	 * that are added to the system.
	 * 
	 * @param observable object that was being obeserved - ignored in this case
	 * @param observedObject object that was added to observable. In this case
	 * 			we are only interested if the object is 
	 * 			an {@link Event}, {@link Attack} or {@link {@link Attack}}object
	 */
	@Override
	public void update(Observable observable, Object observedObject) {
		if (observedObject instanceof Event) {
			Event event = (Event)observedObject;
			
			logger.info("Reporter observed event by user [" + event.getUser().getUsername() + "]");
		} else if (observedObject instanceof Attack) {
			Attack attack = (Attack)observedObject;

			logger.info("Reporter observed attack by user [" + attack.getUser().getUsername() + "]");
		} else if (observedObject instanceof Response) {
			Response response = (Response)observedObject;

			logger.info("Reporter observed response for user [" + response.getUser().getUsername() + "]");
		}
	}

	@Override
	public Collection<Event> findEvents(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	@Override
	public Collection<Attack> findAttacks(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}

	@Override
	public Collection<Response> findResponses(Long earliest) {
		throw new UnsupportedOperationException("This method is not implemented for local logging implementation");
	}
	
}
