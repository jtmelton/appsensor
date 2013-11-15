package org.owasp.appsensor;

public interface UserManager {
	
	public void logout(User user);
	
	public void disable(User user);
	
}
