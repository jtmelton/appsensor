package org.owasp.appsensor.configuration.server;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Test server xml configuration reader
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations={"classpath:base-context.xml"})
public class StaxServerConfigurationReaderTest {
	
//	@Inject
//	ServerConfiguration configuration;
	
	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read();
		
		assertEquals(3, configuration.getCorrelationSets().size());
		assertEquals("server1", configuration.getCorrelationSets().iterator().next().getClientApplications().iterator().next());
		
//		assertEquals("org.owasp.appsensor.analysis.ReferenceEventAnalysisEngine", configuration.getEventAnalysisEngineImplementation());
//		assertEquals("org.owasp.appsensor.analysis.ReferenceAttackAnalysisEngine", configuration.getAttackAnalysisEngineImplementation());
//		assertEquals("org.owasp.appsensor.analysis.ReferenceResponseAnalysisEngine", configuration.getResponseAnalysisEngineImplementation());
//		
//		assertEquals("org.owasp.appsensor.storage.InMemoryEventStore", configuration.getEventStoreImplementation());
//		assertEquals("org.owasp.appsensor.storage.InMemoryAttackStore", configuration.getAttackStoreImplementation());
//		assertEquals("org.owasp.appsensor.storage.InMemoryResponseStore", configuration.getResponseStoreImplementation());
//		
//		assertEquals("org.owasp.appsensor.logging.Slf4jLogger", configuration.getLoggerImplementation());
//		
//		assertEquals("org.owasp.appsensor.accesscontrol.ReferenceAccessController", configuration.getAccessControllerImplementation());
//		
//		assertEquals(2, configuration.getEventStoreObserverImplementations().size());
//		assertEquals("org.owasp.appsensor.analysis.ReferenceEventAnalysisEngine", configuration.getEventStoreObserverImplementations().iterator().next());
//		
//		assertEquals(2, configuration.getAttackStoreObserverImplementations().size());
//		assertEquals("org.owasp.appsensor.analysis.ReferenceAttackAnalysisEngine", configuration.getAttackStoreObserverImplementations().iterator().next());
//		
//		assertEquals(2, configuration.getResponseStoreObserverImplementations().size());
//		assertEquals("org.owasp.appsensor.analysis.ReferenceResponseAnalysisEngine", configuration.getResponseStoreObserverImplementations().iterator().next());
		
		assertEquals(5, configuration.getDetectionPoints().size());
		assertEquals("IE1", configuration.getDetectionPoints().iterator().next().getId());
		assertEquals(4, configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getDuration());
		assertEquals("minutes", configuration.getDetectionPoints().iterator().next().getThreshold().getInterval().getUnit());
		
		assertEquals(5, configuration.getDetectionPoints().iterator().next().getResponses().size());
		assertEquals("log", configuration.getDetectionPoints().iterator().next().getResponses().iterator().next().getAction());
	}
}
