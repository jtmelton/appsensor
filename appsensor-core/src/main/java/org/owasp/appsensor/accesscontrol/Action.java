package org.owasp.appsensor.accesscontrol;

/**
 * This enum gives the options of the types of actions that can be 
 * performed and for which access control needs to be considered
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public enum Action {
	
	ADD_EVENT,
	ADD_ATTACK,
	GET_RESPONSES,
	EXECUTE_REPORT
	
}
