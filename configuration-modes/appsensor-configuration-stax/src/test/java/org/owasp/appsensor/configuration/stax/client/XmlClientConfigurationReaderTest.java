package org.owasp.appsensor.configuration.stax.client;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.owasp.appsensor.configuration.stax.client.StaxClientConfigurationReader;
import org.owasp.appsensor.core.configuration.client.ClientConfiguration;
import org.owasp.appsensor.core.configuration.client.ClientConfigurationReader;

/**
 * Test various configuration settings from the xml client configuration
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations={"classpath:base-context.xml"})
public class XmlClientConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ClientConfigurationReader reader = new StaxClientConfigurationReader();
		ClientConfiguration configuration = reader.read("/appsensor-client-config.xml", "/appsensor_client_config_2.0.xsd");

		assertTrue("rest".equals(configuration.getServerConnection().getType()));
		assertTrue("http://localhost:9000/myapp/".equals(configuration.getServerConnection().getUrl()));
	}
}
