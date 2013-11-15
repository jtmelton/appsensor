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

public class InMemoryAttackStore extends AttackStore {
	
	private static Logger logger = ServerObjectFactory.getLogger().setLoggerClass(InMemoryAttackStore.class);
	
	private Collection<Attack> attacks = new CopyOnWriteArrayList<Attack>();
	
	@Override
	public void addAttack(Attack attack) {
		logger.warning("Security attack " + attack.getDetectionPoint().getId() + " triggered by user: " + attack.getUser().getUsername());
	       
		attacks.add(attack);
		
		super.setChanged();
		
		super.notifyObservers(attack);
	}
	
	@Override
	public Collection<Attack> findAttacks(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds) {
		Collection<Attack> matchingAttacks = new ArrayList<Attack>();
		
		for (Attack attack : attacks) {
			if (user.equals(attack.getUser()) && 
					detectionSystemIds.contains(attack.getDetectionSystemId()) &&
					attack.getDetectionPoint().getId().equals(detectionPoint.getId())) {
				matchingAttacks.add(attack);
			}
		}
		
		return matchingAttacks;
	}
	
}
