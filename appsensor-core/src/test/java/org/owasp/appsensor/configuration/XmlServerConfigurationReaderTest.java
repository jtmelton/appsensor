package org.owasp.appsensor.configuration;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.configuration.server.XmlServerConfigurationReader;

public class XmlServerConfigurationReaderTest {
	
	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new XmlServerConfigurationReader();
		ServerConfiguration configuration = reader.read();
		
		assertEquals(5, configuration.getDetectionPoints().size());
		
		
//		System.err.println("read xml config");
//		System.err.println(configuration);
//		
//		System.err.println("eventAnalysisEngineImplementation: " + configuration.getEventAnalysisEngineImplementation());
//		System.err.println("attackAnalysisEngineImplementation: " + configuration.getAttackAnalysisEngineImplementation());
//		System.err.println("responseAnalysisEngineImplementation: " + configuration.getResponseAnalysisEngineImplementation());
//		System.err.println("eventStoreImplementation: " + configuration.getEventStoreImplementation());
//		System.err.println("attackStoreImplementation: " + configuration.getAttackStoreImplementation());
//		System.err.println("responseStoreImplementation: " + configuration.getResponseStoreImplementation());
//		System.err.println("loggerImplementation: " + configuration.getLoggerImplementation());
//		System.err.println("eventStoreObserverImplementations: " + configuration.getEventStoreObserverImplementations());
//		System.err.println("attackStoreObserverImplementations: " + configuration.getAttackStoreObserverImplementations());
//		System.err.println("responseStoreObserverImplementations: " + configuration.getResponseStoreObserverImplementations());
//		
//		System.err.println("detectionPoints: " + configuration.getDetectionPoints());
//		for(DetectionPoint point : configuration.getDetectionPoints()) {
//			System.err.println();
//			System.err.println("\t id: " + point.getId());
//			System.err.println("\t threshold: " + point.getThreshold().getCount());
//			System.err.println("\t interval: " + point.getThreshold().getInterval().getDuration() + " " + point.getThreshold().getInterval().getUnit());
//			System.err.println("\t responses: ");
//			for(Response response : point.getResponses()) {
//				System.err.println("\t\t response action: " + response.getAction());
//				String intervalString = "";
//				if(response.getInterval() != null && response.getInterval().getUnit() != null) {
//					intervalString = response.getInterval().getDuration() + " " + response.getInterval().getUnit();
//				}
//				System.err.println("\t\t response interval: " + intervalString);
//			}
//			System.err.println();
//		}
//		System.err.println("correlationSets: " + configuration.getCorrelationSets());
	}
}
