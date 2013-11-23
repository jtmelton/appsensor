package org.owasp.appsensor;

/**
 * This is the very basic interface that all Security Control implementations should implement. It is expected that each
 * control/component will have a UUID associated with it so that locater services can locate the implementations based on
 * some registry and to allow multiple instances of single components to exist within an application.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface AccessController {

}
