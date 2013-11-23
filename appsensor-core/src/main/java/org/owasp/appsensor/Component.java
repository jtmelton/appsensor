package org.owasp.appsensor;

import java.util.UUID;

/**
 * This is the very basic interface that all Component implementations should implement. It is expected that each
 * component will have a UUID associated with it so that locater services can locate the implementations based on
 * some registry and to allow multiple instances of single components to exist within an application.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Component {
	
	/**
     * Returns the Unique Identifier for this component/control instance.
     * 
     * @return Unique Identifier for this component/control instance
     */
    UUID getComponentID();
}
