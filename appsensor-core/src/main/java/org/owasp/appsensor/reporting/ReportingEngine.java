package org.owasp.appsensor.reporting;

import java.util.Observer;

/**
 * A reporting engine is an implementation of the Observer pattern. 
 * 
 * It watches implementations of the {@link java.util.Observable} interface. 
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
public interface ReportingEngine extends Observer {

}
