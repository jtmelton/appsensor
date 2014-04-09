package org.owasp.appsensor.analysis;

import org.owasp.appsensor.configuration.Configurable;


/**
 * An analysis engine is an implementation of the Observer pattern. 
 * 
 * It watches implementations of the *Listener interface. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * AnalysisEngine implementations are the components of AppSensor that 
 * constitute the "brain" of the system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface AnalysisEngine extends Configurable {

}
