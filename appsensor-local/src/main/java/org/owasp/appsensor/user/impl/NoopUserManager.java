package org.owasp.appsensor.user.impl;

import org.owasp.appsensor.User;
import org.owasp.appsensor.UserManager;

public class NoopUserManager implements UserManager {

	@Override
	public void logout(User user) {
		//do nothing
	}

	@Override
	public void disable(User user) {
		//do nothing
	}

}
