package org.owasp.appsensor.storage;

import java.util.Collection;
import java.util.Observable;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.User;

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
public abstract class AttackStore extends Observable {
	
	/**
	 * Add an attack to the AttackStore
	 * 
	 * @param attack the {@link org.owasp.appsensor.Attack} object to add to the AttackStore
	 */
	public abstract void addAttack(Attack attack);
	
	/**
	 * Finder for attacks in the AttackStore. 
	 * 
	 * @param user the {@link org.owasp.appsensor.User} object to search by
	 * @param detectionPoint The {@link org.owasp.appsensor.DetectionPoint} to search by
	 * @param detectionSystemIds A {@link java.util.Collection} of detection system ids to search by
	 * @return a {@link java.util.Collection} of {@link org.owasp.appsensor.Attack} objects matching the search criteria.
	 */
	public abstract Collection<Attack> findAttacks(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
	
}
