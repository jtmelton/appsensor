package org.owasp.appsensor.core.listener;

import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.owasp.appsensor.core.storage.ResponseStoreListener;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Response} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@ResponseStoreListener
public interface ResponseListener {
	
	/**
	 * Listener method to handle when a new 
	 * {@link Response} is added to the {@link ResponseStore}
	 * 
	 * @param attack {@link Response} that is added to the {@link ResponseStore}
	 */
	public void onAdd(Response response);
	
}
