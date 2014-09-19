package org.owasp.appsensor.core.listener;

import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.storage.EventStoreListener;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Event} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@EventStoreListener
public interface EventListener {
	
	/**
	 * Listener method to handle when a new 
	 * {@link Event} is added to the {@link EventStore}
	 * 
	 * @param event {@link Event} that is added to the {@link EventStore}
	 */
	public void onAdd(Event event);
}
