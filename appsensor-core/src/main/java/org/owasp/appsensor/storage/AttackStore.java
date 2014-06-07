package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.inject.Inject;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.AttackListener;

/**
 * A store is an observable object. 
 * 
 * It is watched by implementations of the {@link AttackListener} interfaces. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
public abstract class AttackStore {
	
	private static Collection<AttackListener> listeners = new CopyOnWriteArrayList<>();
	
	/**
	 * Add an attack to the AttackStore
	 * 
	 * @param attack the {@link org.owasp.appsensor.Attack} object to add to the AttackStore
	 */
	public abstract void addAttack(Attack attack);
	
	/**
	 * Finder for attacks in the AttackStore. 
	 * 
	 * @param criteria the {@link org.owasp.appsensor.criteria.SearchCriteria} object to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Attack} objects matching the search criteria.
	 */
	public abstract Collection<Attack> findAttacks(SearchCriteria criteria);
	
	/**
	 * Register an {@link AttackListener} to notify when {@link Attack}s are added
	 * 
	 * @param listener the {@link AttackListener} to register
	 */
	public void registerListener(AttackListener listener) {
		if (! listeners.contains(listener)) {
			boolean unique = true;
			
			for (AttackListener existing : listeners) {
				if (existing.getClass().equals(listener.getClass())) {
					unique = false;
					break;
				}
			}
			
			if (unique) {
				listeners.add(listener);
			}
		}
	}
	
	/**
	 * Notify each {@link AttackListener} of the specified {@link Attack}
	 * 
	 * @param response the {@link Attack} to notify each {@link AttackListener} about
	 */
	public void notifyListeners(Attack attack) {
		for (AttackListener listener : listeners) {
			listener.onAdd(attack);
		}
	}
	
	/**
	 * Automatically inject any {@link @AttackStoreListener}s, which are implementations of 
	 * {@link AttackListener} so they can be notified of changes.
	 * 
	 * @param collection of {@link AttackListener}s that are injected to be 
	 * 			listeners on the {@link @AttackStore}
	 */
	@Inject @AttackStoreListener
	public void setListeners(Collection<AttackListener> listeners) {
		for (AttackListener listener : listeners) {
			registerListener(listener);	
		}
	}
	
}
