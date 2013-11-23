package org.owasp.appsensor;

import java.io.Serializable;

/**
 * Role is the standard attribution of an access to be used by the {@link AccessController} 
 * to determine client application access to the different pieces of functionality.
 * 
 * @see java.io.Serializable
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Role extends Serializable {

}
