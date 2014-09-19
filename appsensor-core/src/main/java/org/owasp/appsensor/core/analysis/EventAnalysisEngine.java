package org.owasp.appsensor.core.analysis;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.listener.EventListener;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.storage.EventStoreListener;

/**
 * The event analysis engine is an implementation of the Observer pattern. 
 * 
 * In this case the analysis engines watches the {@link EventStore} interface.
 * 
 * AnalysisEngine implementations are the components of AppSensor that 
 * constitute the "brain" of the system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@EventStoreListener
public abstract class EventAnalysisEngine implements EventListener {

	public void onAdd(Event event) {
		analyze(event);
	}
	
	public abstract void analyze(Event event);
	
}
