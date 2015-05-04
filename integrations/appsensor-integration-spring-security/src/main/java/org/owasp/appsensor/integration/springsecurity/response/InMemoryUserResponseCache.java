package org.owasp.appsensor.integration.springsecurity.response;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Named;

/**
 * This is a simple in-memory implementation of the 
 * {@link UserResponseCache} interface to track the 
 * logout status of users.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class InMemoryUserResponseCache implements UserResponseCache {

	private static Map<String, Boolean> loggedOutUsers = Collections.synchronizedMap(new HashMap<String, Boolean>());
	
	@Override
	public boolean isUserLoggedOut(String userName) {
		return loggedOutUsers.keySet().contains(userName);
	}

	@Override
	public void setUserLoggedOut(String userName) {
		loggedOutUsers.put(userName, Boolean.FALSE);
	}

	@Override
	public void clearUserLoggedOut(String userName) {
		loggedOutUsers.remove(userName);
	}

	@Override
	public boolean isLogoutProcessed(String userName) {
		return loggedOutUsers.keySet().contains(userName) && 
				Boolean.TRUE.equals(loggedOutUsers.get(userName));
	}

	@Override
	public void processLogout(String userName) {
		loggedOutUsers.put(userName, Boolean.TRUE);
	}
}
