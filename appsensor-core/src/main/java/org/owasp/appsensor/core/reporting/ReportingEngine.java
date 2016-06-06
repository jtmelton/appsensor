package org.owasp.appsensor.core.reporting;

import java.util.Collection;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.KeyValuePair;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.exceptions.NotAuthorizedException;
import org.owasp.appsensor.core.listener.AttackListener;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.listener.ResponseListener;

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
public interface ReportingEngine extends EventListener, AttackListener, ResponseListener {

	/**
	 * Find {@link Event}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @return Collection of {@link Event}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Event> findEvents(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Attack}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Attack}s (RFC-3339)
	 * @return Collection of {@link Attack}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Attack> findAttacks(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Response}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Response}s (RFC-3339)
	 * @return Collection of {@link Response}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public Collection<Response> findResponses(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Event}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @return count of Collection of {@link Event}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countEvents(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Attack}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Attack}s (RFC-3339)
	 * @return count of Collection of {@link Attack}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countAttacks(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Response}s starting from specified time (unix timestamp)
	 * 
	 * @param earliest String representing start time to use to find {@link Response}s (RFC-3339)
	 * @return count of Collection of {@link Response}s from starting time
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countResponses(String earliest) throws NotAuthorizedException;
	
	/**
	 * Find {@link Event}s starting from specified time (unix timestamp) matching label
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param label String representing detection point label
	 * @return count of Collection of {@link Event}s from starting time matching label
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countEventsByLabel(String earliest, String label) throws NotAuthorizedException;
	
	/**
	 * Find {@link Attack}s starting from specified time (unix timestamp) matching label
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param label String representing detection point label
	 * @return count of Collection of {@link Event}s from starting time matching label
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countAttacksByLabel(String earliest, String label) throws NotAuthorizedException;
	
	/**
	 * Find {@link Response}s starting from specified time (unix timestamp) matching label
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param label String representing detection point label
	 * @return count of Collection of {@link Event}s from starting time matching label
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countResponsesByLabel(String earliest, String label) throws NotAuthorizedException;
	
	/**
	 * Find {@link Event}s starting from specified time (unix timestamp) matching user
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param user String representing user
	 * @return count of Collection of {@link Event}s from starting time matching user
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countEventsByUser(String earliest, String user) throws NotAuthorizedException;
	
	/**
	 * Find {@link Attack}s starting from specified time (unix timestamp) matching user
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param user String representing user
	 * @return count of Collection of {@link Event}s from starting time matching user
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countAttacksByUser(String earliest, String user) throws NotAuthorizedException;
	
	/**
	 * Find {@link Response}s starting from specified time (unix timestamp) matching user
	 * 
	 * @param earliest String representing start time to use to find {@link Event}s (RFC-3339)
	 * @param user String representing user
	 * @return count of Collection of {@link Event}s from starting time matching user
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public int countResponsesByUser(String earliest, String user) throws NotAuthorizedException;
	
	/**
	 * Return the {@link ServerConfiguration} as JSON
	 * 
	 * @return the {@link ServerConfiguration} as JSON
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public String getServerConfigurationAsJson() throws NotAuthorizedException;
	
	/**
	 * Return a base-64 encoded version of the appsensor-server-config.xml
	 * 
	 * @return a base-64 encoded version of the appsensor-server-config.xml
	 * @throws NotAuthorizedException thrown if {@link ClientApplication} is not authorized for reporting
	 */
	public KeyValuePair getBase64EncodedServerConfigurationFileContent() throws NotAuthorizedException;
	
}
