package org.owasp.appsensor.configuration.stax.server;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.appsensor.configuration.stax.server.StaxServerConfigurationReader;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.configuration.server.ServerConfigurationReader;

/**
 * Test server xml configuration reader
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class StaxServerConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read();
		
		assertEquals(3, configuration.getCorrelationSets().size());
		assertEquals("server1", configuration.getCorrelationSets().iterator().next().getClientApplications().iterator().next());
		
		assertEquals(1, configuration.getCustomDetectionPoints().size());
		//assertEquals("server1", configuration.getCorrelationSets().iterator().next().getClientApplications().iterator().next());
		
		assertEquals(5, configuration.getDetectionPoints().size());
		assertEquals("IE1", configuration.getDetectionPoints().iterator().next().getLabel());
		assertEquals(4, configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getDuration());
		assertEquals("minutes", configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getUnit());
		
		assertEquals(5, configuration.getDetectionPoints().iterator().next().getResponses().size());
		assertEquals("log", configuration.getDetectionPoints().iterator().next().getResponses().iterator().next().getAction());
	}
}
