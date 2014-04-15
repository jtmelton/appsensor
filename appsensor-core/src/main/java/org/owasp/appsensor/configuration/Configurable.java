package org.owasp.appsensor.configuration;

/**
 * Interface that states objects implementing this are able to provide
 * custom {@link ExtendedConfiguration}s. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Configurable {

	public ExtendedConfiguration getExtendedConfiguration();
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration);
	
}
