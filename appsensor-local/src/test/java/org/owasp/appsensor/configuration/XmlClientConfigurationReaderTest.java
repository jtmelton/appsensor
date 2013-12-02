package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.StaxClientConfigurationReader;

public class XmlClientConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ClientConfigurationReader reader = new StaxClientConfigurationReader();
		ClientConfiguration configuration = reader.read("/appsensor-client-config.xml", "/appsensor_client_config_2.0.xsd");
		
		assertTrue("org.owasp.appsensor.event.impl.LocalEventManager".equals(configuration.getEventManagerImplementation()));
		assertTrue("org.owasp.appsensor.response.impl.NoopResponseHandler".equals(configuration.getResponseHandlerImplementation()));
		assertTrue("org.owasp.appsensor.user.impl.NoopUserManager".equals(configuration.getUserManagerImplementation()));
		assertTrue("rest".equals(configuration.getServerConnection().getType()));
		assertTrue("https".equals(configuration.getServerConnection().getProtocol()));
		assertTrue("www.owasp.org".equals(configuration.getServerConnection().getHost()));
		assertTrue(5000 == configuration.getServerConnection().getPort());
		assertTrue("/appsensor/v2/api/".equals(configuration.getServerConnection().getPath()));
	}
}
