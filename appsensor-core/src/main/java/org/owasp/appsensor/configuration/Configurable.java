package org.owasp.appsensor.configuration;

/**
 * Interface that states objects implementing this are able to provide
 * custom {@link ExtendedConfiguration}s. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public interface Configurable {

	/**
	 * Retrieve the {@link ExtendedConfiguration} object.
	 * @return the {@link ExtendedConfiguration} object
	 */
	public ExtendedConfiguration getExtendedConfiguration();
	
	/**
	 * Set the {@link ExtendedConfiguration} object.
	 * @param extendedConfiguration the {@link ExtendedConfiguration} object
	 */
	public void setExtendedConfiguration(ExtendedConfiguration extendedConfiguration);
	
}
