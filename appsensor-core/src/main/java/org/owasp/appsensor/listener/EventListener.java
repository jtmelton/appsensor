package org.owasp.appsensor.listener;

import org.owasp.appsensor.Event;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Event} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface EventListener {
	public void onAdd(Event event);
}
