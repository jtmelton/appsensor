package org.owasp.appsensor.listener;

import org.owasp.appsensor.Response;
import org.owasp.appsensor.storage.ResponseStore;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Response} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface ResponseListener {
	
	/**
	 * Listener method to handle when a new 
	 * {@link Response} is added to the {@link ResponseStore}
	 * 
	 * @param attack {@link Response} that is added to the {@link ResponseStore}
	 */
	public void onAdd(Response response);
	
}
