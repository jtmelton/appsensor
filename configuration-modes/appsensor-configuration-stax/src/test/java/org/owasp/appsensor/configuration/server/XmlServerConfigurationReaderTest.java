package org.owasp.appsensor.configuration.server;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Test various configuration settings from the xml server configuration
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations={"classpath:base-context.xml"})
public class XmlServerConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-config.xml", "/appsensor_server_config_2.0.xsd");
		
//		assertTrue("org.owasp.appsensor.analysis.ReferenceEventAnalysisEngine".equals(configuration.getEventAnalysisEngineImplementation()));
		assertEquals("X-Appsensor-Client-Application-Name2", configuration.getClientApplicationIdentificationHeaderName());
		
	}
}
