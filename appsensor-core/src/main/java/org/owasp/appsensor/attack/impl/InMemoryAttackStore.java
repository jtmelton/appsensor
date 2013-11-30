package org.owasp.appsensor.attack.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.CopyOnWriteArrayList;

import org.owasp.appsensor.Attack;
import org.owasp.appsensor.AttackStore;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Logger;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.User;

/**
 * This is a reference implementation of the attack store, and is an implementation of the Observable pattern.
 * 
 * It notifies implementations of the {@link java.util.Observer} interface and passes the observed object. 
 * In this case, we are only concerned with {@link org.owasp.appsensor.Attack} implementations. 
 * 
 * The implementation is trivial and simply stores the Attacks in an in-memory collection.
 * 
 * @see java.util.Observable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InMemoryAttackStore extends AttackStore {
	
	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(InMemoryAttackStore.class);
	
	private Collection<Attack> attacks = new CopyOnWriteArrayList<Attack>();
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addAttack(Attack attack) {
		logger.warning("Security attack " + attack.getDetectionPoint().getId() + " triggered by user: " + attack.getUser().getUsername());
	       
		attacks.add(attack);
		
		super.setChanged();
		
		super.notifyObservers(attack);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Collection<Attack> findAttacks(User user, DetectionPoint search, Collection<String> detectionSystemIds) {
		Collection<Attack> matchingAttacks = new ArrayList<Attack>();
		
		for (Attack attack : attacks) {
			if (user.equals(attack.getUser()) && 
					detectionSystemIds.contains(attack.getDetectionSystemId()) &&
					attack.getDetectionPoint().getId().equals(search.getId())) {
				matchingAttacks.add(attack);
			}
		}
		
		return matchingAttacks;
	}
	
}
