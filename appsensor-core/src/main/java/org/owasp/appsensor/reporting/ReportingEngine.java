package org.owasp.appsensor.reporting;

import java.util.Collection;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.exceptions.NotAuthorizedException;
import org.owasp.appsensor.listener.AttackListener;
import org.owasp.appsensor.listener.EventListener;
import org.owasp.appsensor.listener.ResponseListener;

/**
 * A reporting engine is an implementation of the observer pattern. 
 * 
 * In this case the reporting engines watch the *Store interfaces of AppSensor.
 * 
 * The reporting engines are meant to provide simple access to get notified 
 * when the different components are added to the *Store's for reporting.
 * 
 * @see java.util.Observer
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface ReportingEngine extends EventListener, AttackListener, ResponseListener {

	public Collection<Event> findEvents(Long earliest) throws NotAuthorizedException;
	
	public Collection<Attack> findAttacks(Long earliest) throws NotAuthorizedException;
	
	public Collection<Response> findResponses(Long earliest) throws NotAuthorizedException;
	
}
