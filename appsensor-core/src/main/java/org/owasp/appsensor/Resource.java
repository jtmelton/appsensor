package org.owasp.appsensor;

import java.io.Serializable;

/**
 * Resource represents a generic component of an application. In many cases, 
 * it would represent a URL, but it could also presumably be used for something 
 * else, such as a specific object, function, or even a subsection of an appliction, etc.
 * 
 * TODO: This may be removed if we only need a String in the Event/Attack objects
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Resource extends Serializable {

}
