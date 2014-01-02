package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.configuration.server.StaxServerConfigurationReader;

/**
 * Test various configuration settings from the xml server configuration
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class XmlServerConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-config.xml", "/appsensor_server_config_2.0.xsd");
		
		assertTrue("org.owasp.appsensor.analysis.ReferenceStatisticalEventAnalysisEngine".equals(configuration.getEventAnalysisEngineImplementation()));
	}
}
