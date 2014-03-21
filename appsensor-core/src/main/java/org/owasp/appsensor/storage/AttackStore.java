package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.criteria.SearchCriteria;
import org.owasp.appsensor.listener.AttackListener;

/**
 * A store is an implementation of the Observable pattern. 
 * 
 * It is watched by implementations of the {@link java.util.Observer} interface. 
 * 
 * In this case the analysis engines watch the *Store interfaces of AppSensor.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public abstract class AttackStore { //extends Observable {
	
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
	
	public void registerListener(AttackListener listener) {
		if (! listeners.contains(listener)) {
			listeners.add(listener);
		}
	}
	
	public void notifyListeners(Attack attack) {
		for (AttackListener listener : listeners) {
			listener.onAdd(attack);
		}
	}
}
