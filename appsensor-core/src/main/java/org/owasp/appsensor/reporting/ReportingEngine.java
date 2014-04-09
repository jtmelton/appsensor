package org.owasp.appsensor.reporting;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.configuration.Configurable;
import org.owasp.appsensor.exceptions.NotAuthorizedException;
import org.owasp.appsensor.listener.AttackListener;
import org.owasp.appsensor.listener.EventListener;
import org.owasp.appsensor.listener.ResponseListener;

/**
 * A reporting engine is an implementation of the observer pattern and 
 * extends the *Listener interfaces. 
 * 
 * In this case the reporting engines watch the *Store interfaces of AppSensor.
 * 
 * The reporting engines are meant to provide simple access to get notified 
 * when the different components are added to the *Store's for reporting.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface ReportingEngine extends EventListener, AttackListener, ResponseListener, Configurable {

	/**
	 * Find {@link Event}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest long representing start time to use to find {@link Event}s
	 * @return Collection of {@link Event}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Event> findEvents(Long earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Attack}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest long representing start time to use to find {@link Attack}s
	 * @return Collection of {@link Attack}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Attack> findAttacks(Long earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Response}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest long representing start time to use to find {@link Response}s
	 * @return Collection of {@link Response}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Response> findResponses(Long earliest) throws NotAuthorizedException;
	
}
