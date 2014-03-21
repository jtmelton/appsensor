package org.owasp.appsensor.listener;

import org.owasp.appsensor.Attack;

public interface AttackListener {
	public void onAdd(Attack attack);
}
