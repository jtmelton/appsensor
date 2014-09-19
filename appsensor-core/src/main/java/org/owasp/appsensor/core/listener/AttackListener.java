package org.owasp.appsensor.core.listener;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.storage.AttackStoreListener;

/**
 * This interface is implemented by classes that want to be notified
 * when a new {@link Attack} is created and stored in the AppSensor system. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@AttackStoreListener
public interface AttackListener {
	
	/**
	 * Listener method to handle when a new 
	 * {@link Attack} is added to the {@link AttackStore}
	 * 
	 * @param attack {@link Attack} that is added to the {@link AttackStore}
	 */
	public void onAdd(Attack attack);
	
}
