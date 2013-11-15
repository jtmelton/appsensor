package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.appsensor.configuration.client.ClientConfiguration;
import org.owasp.appsensor.configuration.client.ClientConfigurationReader;
import org.owasp.appsensor.configuration.client.XmlClientConfigurationReader;

public class XmlClientConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ClientConfigurationReader reader = new XmlClientConfigurationReader();
		ClientConfiguration configuration = reader.read("/appsensor-client-config.xml", "/appsensor_client_config_2.0.xsd");
		
		assertTrue("org.owasp.appsensor.event.impl.LocalEventManager".equals(configuration.getEventManagerImplementation()));
//		System.err.println("read xml config");
//		System.err.println(configuration);
//		System.err.println(configuration.getServerConnection());
		
	}
}
