package org.owasp.appsensor;

import java.io.Serializable;

/**
 * Resource represents a generic component of an application. In many cases, 
 * it would represent a URL, but it could also presumably be used for something 
 * else, such as a specific object, function, or even a subsection of an appliction, etc.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class Resource implements Serializable {
	
	private static final long serialVersionUID = 343899601431699577L;

	/** 
	 * The resource being requested when a given event/attack was triggered, which can be used 
     * later to block requests to a given function.  In this implementation, 
     * the current request URI is used.
     */
	private String location;

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}
	
}
