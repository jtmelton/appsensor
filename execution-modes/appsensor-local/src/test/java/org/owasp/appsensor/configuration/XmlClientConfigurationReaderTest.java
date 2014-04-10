package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.StaxClientConfigurationReader;

/**
 * Test various configuration settings from the xml client configuration
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class XmlClientConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ClientConfigurationReader reader = new StaxClientConfigurationReader();
		ClientConfiguration configuration = reader.read("/appsensor-client-config.xml", "/appsensor_client_config_2.0.xsd");
		
		assertTrue("org.owasp.appsensor.event.LocalEventManager".equals(configuration.getEventManagerImplementation()));
		assertTrue("org.owasp.appsensor.response.LocalResponseHandler".equals(configuration.getResponseHandlerImplementation()));
		assertTrue("org.owasp.appsensor.response.NoopUserManager".equals(configuration.getUserManagerImplementation()));
		assertTrue("rest".equals(configuration.getServerConnection().getType()));
		assertTrue("https".equals(configuration.getServerConnection().getProtocol()));
		assertTrue("www.owasp.org".equals(configuration.getServerConnection().getHost()));
		assertTrue(5000 == configuration.getServerConnection().getPort());
		assertTrue("/appsensor/v2/api/".equals(configuration.getServerConnection().getPath()));
	}
}
