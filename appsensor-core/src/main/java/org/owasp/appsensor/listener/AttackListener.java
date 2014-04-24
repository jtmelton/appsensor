package org.owasp.appsensor.listener;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.configuration.Configurable;
import org.owasp.appsensor.storage.AttackStore;
import org.owasp.appsensor.storage.AttackStoreListener;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Attack} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@AttackStoreListener
public interface AttackListener extends Configurable {
	
	/**
	 * Listener method to handle when a new 
	 * {@link Attack} is added to the {@link AttackStore}
	 * 
	 * @param attack {@link Attack} that is added to the {@link AttackStore}
	 */
	public void onAdd(Attack attack);
	
}
