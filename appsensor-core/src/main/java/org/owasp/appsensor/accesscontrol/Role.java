package org.owasp.appsensor.accesscontrol;

/**
 * Role is the standard attribution of an access to be used by the {@link AccessController} 
 * to determine client application access to the different pieces of functionality.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public enum Role { 
	
	ADD_EVENT,
	ADD_ATTACK,
	GET_RESPONSES,
	EXECUTE_REPORT
	
}
