package org.owasp.appsensor.configuration.server;

import java.util.Collection;

import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.correlation.CorrelationSet;

public interface ServerConfiguration {
	
	public String getEventAnalysisEngineImplementation();

	public ServerConfiguration setEventAnalysisEngineImplementation(String eventAnalysisEngineImplementation);

	public String getAttackAnalysisEngineImplementation();

	public ServerConfiguration setAttackAnalysisEngineImplementation(String attackAnalysisEngineImplementation);

	public String getResponseAnalysisEngineImplementation();

	public ServerConfiguration setResponseAnalysisEngineImplementation(String responseAnalysisEngineImplementation);

	public String getEventStoreImplementation();

	public ServerConfiguration setEventStoreImplementation(String eventStoreImplementation);

	public String getAttackStoreImplementation();

	public ServerConfiguration setAttackStoreImplementation(String attackStoreImplementation);

	public String getResponseStoreImplementation();

	public ServerConfiguration setResponseStoreImplementation(String responseStoreImplementation);
	
	public String getLoggerImplementation();

	public ServerConfiguration setLoggerImplementation(String loggerImplementation);
	
	public String getResponseHandlerImplementation();

	public ServerConfiguration setResponseHandlerImplementation(String responseHandlerImplementation);
	
	public Collection<String> getEventStoreObserverImplementations();

	public ServerConfiguration setEventStoreObserverImplementations(Collection<String> eventStoreObserverImplementations);

	public Collection<String> getAttackStoreObserverImplementations();

	public ServerConfiguration setAttackStoreObserverImplementations(Collection<String> attackStoreObserverImplementations);

	public Collection<String> getResponseStoreObserverImplementations();

	public ServerConfiguration setResponseStoreObserverImplementations(Collection<String> responseStoreObserverImplementations);
	
	public Collection<DetectionPoint> getDetectionPoints();

	public ServerConfiguration setDetectionPoints(Collection<DetectionPoint> detectionPoints);
	
	public Collection<CorrelationSet> getCorrelationSets();

	public ServerConfiguration setCorrelationSets(Collection<CorrelationSet> correlationSets);
	
	/**
	 * Find related detection systems based on a given detection system. 
	 * This simply means those systems that have been configured along with the 
	 * specified system id as part of a correlation set. 
	 * 
	 * @param detectionSystemId system ID to evaluate and find correlated systems
	 * @return collection of strings representing correlation set, INCLUDING specified system ID
	 */
	public Collection<String> getRelatedDetectionSystems(String detectionSystemId);
	
	/**
	 * Locate detection point configuration from server-side config file. 
	 * 
	 * @param search detection point that has been added to the system
	 * @return DetectionPoint populated with configuration information from server-side config
	 */
	public DetectionPoint findDetectionPoint(DetectionPoint search);

}
