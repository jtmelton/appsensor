package org.owasp.appsensor.core;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * Resource represents a generic component of an application. In many cases, 
 * it would represent a URL, but it could also presumably be used for something 
 * else, such as a specific object, function, or even a subsection of an application, etc.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Entity
public class Resource implements Serializable {
	
	private static final long serialVersionUID = 343899601431699577L;

	@Id
	@Column
	@GeneratedValue
	private Integer id;
	
	/** 
	 * The resource being requested when a given event/attack was triggered, which can be used 
     * later to block requests to a given function.  In this implementation, 
     * the current request URI is used.
     */
	@Column
	private String location;

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}
	
}
