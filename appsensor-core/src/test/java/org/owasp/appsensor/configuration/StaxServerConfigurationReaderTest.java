package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.configuration.server.StaxServerConfigurationReader;

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
		
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceStatisticalEventAnalysisEngine", configuration.getEventAnalysisEngineImplementation());
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceAttackAnalysisEngine", configuration.getAttackAnalysisEngineImplementation());
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceResponseAnalysisEngine", configuration.getResponseAnalysisEngineImplementation());
		
		assertEquals("org.owasp.appsensor.event.impl.InMemoryEventStore", configuration.getEventStoreImplementation());
		assertEquals("org.owasp.appsensor.attack.impl.InMemoryAttackStore", configuration.getAttackStoreImplementation());
		assertEquals("org.owasp.appsensor.response.impl.InMemoryResponseStore", configuration.getResponseStoreImplementation());
		
		assertEquals("org.owasp.appsensor.logging.impl.Slf4jLogger", configuration.getLoggerImplementation());
		
		assertEquals("org.owasp.appsensor.response.impl.ReferenceResponseHandler", configuration.getResponseHandlerImplementation());
		
		assertEquals(2, configuration.getEventStoreObserverImplementations().size());
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceStatisticalEventAnalysisEngine", configuration.getEventStoreObserverImplementations().iterator().next());
		
		assertEquals(2, configuration.getAttackStoreObserverImplementations().size());
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceAttackAnalysisEngine", configuration.getAttackStoreObserverImplementations().iterator().next());
		
		assertEquals(2, configuration.getResponseStoreObserverImplementations().size());
		assertEquals("org.owasp.appsensor.analysis.impl.ReferenceResponseAnalysisEngine", configuration.getResponseStoreObserverImplementations().iterator().next());
		
		assertEquals(5, configuration.getDetectionPoints().size());
		assertEquals("IE1", configuration.getDetectionPoints().iterator().next().getId());
		assertEquals(4, configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getDuration());
		assertEquals("minutes", configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getUnit());
		
		assertEquals(5, configuration.getDetectionPoints().iterator().next().getResponses().size());
		assertEquals("log", configuration.getDetectionPoints().iterator().next().getResponses().iterator().next().getAction());
	}
}
