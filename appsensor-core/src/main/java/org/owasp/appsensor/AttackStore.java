package org.owasp.appsensor;

import java.util.Collection;
import java.util.Observable;

public abstract class AttackStore extends Observable {
	public abstract void addAttack(Attack attack);
	public abstract Collection<Attack> findAttacks(User user, DetectionPoint detectionPoint, Collection<String> detectionSystemIds);
}
