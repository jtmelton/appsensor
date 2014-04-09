package org.owasp.appsensor.configuration.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.ClientApplication;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.configuration.ExtendedConfiguration;
import org.owasp.appsensor.correlation.CorrelationSet;

/**
 * Represents the configuration for server-side components. Additionally, 
 * contains various helper methods for common configuration-related 
 * actions.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ServerConfiguration {
	
	private String eventAnalysisEngineImplementation;
	private ExtendedConfiguration eventAnalysisEngineExtendedConfiguration;
	private String attackAnalysisEngineImplementation;
	private ExtendedConfiguration attackAnalysisEngineExtendedConfiguration;
	private String responseAnalysisEngineImplementation;
	private ExtendedConfiguration responseAnalysisEngineExtendedConfiguration;
	
	private String eventStoreImplementation;
	private ExtendedConfiguration eventStoreExtendedConfiguration;
	private String attackStoreImplementation;
	private ExtendedConfiguration attackStoreExtendedConfiguration;
	private String responseStoreImplementation;
	private ExtendedConfiguration responseStoreExtendedConfiguration;
	
	private String loggerImplementation;
	private ExtendedConfiguration loggerExtendedConfiguration;
	
	private String accessControllerImplementation;
	private ExtendedConfiguration accessControllerExtendedConfiguration;
	
	private Collection<String> eventStoreObserverImplementations = new ArrayList<>();
	private Collection<String> attackStoreObserverImplementations = new ArrayList<>();
	private Collection<String> responseStoreObserverImplementations = new ArrayList<>();
	
	private Collection<DetectionPoint> detectionPoints = new ArrayList<>(); 
	
	private Collection<CorrelationSet> correlationSets = new HashSet<>();
	
	private String clientApplicationIdentificationHeaderName;
	
	private Collection<ClientApplication> clientApplications = new HashSet<>();
	
	private static transient Map<String, DetectionPoint> detectionPointCache = Collections.synchronizedMap(new HashMap<String, DetectionPoint>());
	
	private static transient Map<String, ClientApplication> clientApplicationCache = Collections.synchronizedMap(new HashMap<String, ClientApplication>());
	
	public String getEventAnalysisEngineImplementation() {
		return eventAnalysisEngineImplementation;
	}
	
	public ServerConfiguration setEventAnalysisEngineImplementation(
			String eventAnalysisEngineImplementation) {
		this.eventAnalysisEngineImplementation = eventAnalysisEngineImplementation;
		return this;
	}

	public String getAttackAnalysisEngineImplementation() {
		return attackAnalysisEngineImplementation;
	}

	public ServerConfiguration setAttackAnalysisEngineImplementation(
			String attackAnalysisEngineImplementation) {
		this.attackAnalysisEngineImplementation = attackAnalysisEngineImplementation;
		return this;
	}

	public String getResponseAnalysisEngineImplementation() {
		return responseAnalysisEngineImplementation;
	}

	public ServerConfiguration setResponseAnalysisEngineImplementation(
			String responseAnalysisEngineImplementation) {
		this.responseAnalysisEngineImplementation = responseAnalysisEngineImplementation;
		return this;
	}

	public String getEventStoreImplementation() {
		return eventStoreImplementation;
	}

	public ServerConfiguration setEventStoreImplementation(String eventStoreImplementation) {
		this.eventStoreImplementation = eventStoreImplementation;
		return this;
	}

	public String getAttackStoreImplementation() {
		return attackStoreImplementation;
	}

	public ServerConfiguration setAttackStoreImplementation(String attackStoreImplementation) {
		this.attackStoreImplementation = attackStoreImplementation;
		return this;
	}

	public String getResponseStoreImplementation() {
		return responseStoreImplementation;
	}

	public ServerConfiguration setResponseStoreImplementation(String responseStoreImplementation) {
		this.responseStoreImplementation = responseStoreImplementation;
		return this;
	}

	public String getLoggerImplementation() {
		return loggerImplementation;
	}

	public ServerConfiguration setLoggerImplementation(String loggerImplementation) {
		this.loggerImplementation = loggerImplementation;
		return this;
	}
	
	public String getAccessControllerImplementation() {
		return accessControllerImplementation;
	}

	public ServerConfiguration setAccessControllerImplementation(
			String accessControllerImplementation) {
		this.accessControllerImplementation = accessControllerImplementation;
		return this;
	}

	public Collection<String> getEventStoreObserverImplementations() {
		return eventStoreObserverImplementations;
	}

	public ServerConfiguration setEventStoreObserverImplementations(
			Collection<String> eventStoreObserverImplementations) {
		this.eventStoreObserverImplementations = eventStoreObserverImplementations;
		return this;
	}

	public Collection<String> getAttackStoreObserverImplementations() {
		return attackStoreObserverImplementations;
	}

	public ServerConfiguration setAttackStoreObserverImplementations(
			Collection<String> attackStoreObserverImplementations) {
		this.attackStoreObserverImplementations = attackStoreObserverImplementations;
		return this;
	}

	public Collection<String> getResponseStoreObserverImplementations() {
		return responseStoreObserverImplementations;
	}

	public ServerConfiguration setResponseStoreObserverImplementations(
			Collection<String> responseStoreObserverImplementations) {
		this.responseStoreObserverImplementations = responseStoreObserverImplementations;
		return this;
	}
	
	public Collection<DetectionPoint> getDetectionPoints() {
		return detectionPoints;
	}

	public ServerConfiguration setDetectionPoints(Collection<DetectionPoint> detectionPoints) {
		this.detectionPoints = detectionPoints;
		return this;
	}
	
	public Collection<CorrelationSet> getCorrelationSets() {
		return correlationSets;
	}

	public ServerConfiguration setCorrelationSets(Collection<CorrelationSet> correlationSets) {
		this.correlationSets = correlationSets;
		return this;
	}
	
	public String getClientApplicationIdentificationHeaderName() {
		return clientApplicationIdentificationHeaderName;
	}

	public ServerConfiguration setClientApplicationIdentificationHeaderName(
			String clientApplicationIdentificationHeaderName) {
		this.clientApplicationIdentificationHeaderName = clientApplicationIdentificationHeaderName;
		return this;
	}

	public Collection<ClientApplication> getClientApplications() {
		return clientApplications;
	}

	public ServerConfiguration setClientApplications(Collection<ClientApplication> clientApplications) {
		this.clientApplications = clientApplications;
		return this;
	}

	public ExtendedConfiguration getEventAnalysisEngineExtendedConfiguration() {
		return eventAnalysisEngineExtendedConfiguration;
	}

	public ServerConfiguration setEventAnalysisEngineExtendedConfiguration(
			ExtendedConfiguration eventAnalysisEngineExtendedConfiguration) {
		this.eventAnalysisEngineExtendedConfiguration = eventAnalysisEngineExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getAttackAnalysisEngineExtendedConfiguration() {
		return attackAnalysisEngineExtendedConfiguration;
	}

	public ServerConfiguration setAttackAnalysisEngineExtendedConfiguration(
			ExtendedConfiguration attackAnalysisEngineExtendedConfiguration) {
		this.attackAnalysisEngineExtendedConfiguration = attackAnalysisEngineExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getResponseAnalysisEngineExtendedConfiguration() {
		return responseAnalysisEngineExtendedConfiguration;
	}

	public ServerConfiguration setResponseAnalysisEngineExtendedConfiguration(
			ExtendedConfiguration responseAnalysisEngineExtendedConfiguration) {
		this.responseAnalysisEngineExtendedConfiguration = responseAnalysisEngineExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getEventStoreExtendedConfiguration() {
		return eventStoreExtendedConfiguration;
	}

	public ServerConfiguration setEventStoreExtendedConfiguration(
			ExtendedConfiguration eventStoreExtendedConfiguration) {
		this.eventStoreExtendedConfiguration = eventStoreExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getAttackStoreExtendedConfiguration() {
		return attackStoreExtendedConfiguration;
	}

	public ServerConfiguration setAttackStoreExtendedConfiguration(
			ExtendedConfiguration attackStoreExtendedConfiguration) {
		this.attackStoreExtendedConfiguration = attackStoreExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getResponseStoreExtendedConfiguration() {
		return responseStoreExtendedConfiguration;
	}

	public ServerConfiguration setResponseStoreExtendedConfiguration(
			ExtendedConfiguration responseStoreExtendedConfiguration) {
		this.responseStoreExtendedConfiguration = responseStoreExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getLoggerExtendedConfiguration() {
		return loggerExtendedConfiguration;
	}

	public ServerConfiguration setLoggerExtendedConfiguration(
			ExtendedConfiguration loggerExtendedConfiguration) {
		this.loggerExtendedConfiguration = loggerExtendedConfiguration;
		return this;
	}

	public ExtendedConfiguration getAccessControllerExtendedConfiguration() {
		return accessControllerExtendedConfiguration;
	}

	public ServerConfiguration setAccessControllerExtendedConfiguration(
			ExtendedConfiguration accessControllerExtendedConfiguration) {
		this.accessControllerExtendedConfiguration = accessControllerExtendedConfiguration;
		return this;
	}

	/**
	 * Find related detection systems based on a given detection system. 
	 * This simply means those systems that have been configured along with the 
	 * specified system id as part of a correlation set. 
	 * 
	 * @param detectionSystemId system ID to evaluate and find correlated systems
	 * @return collection of strings representing correlation set, INCLUDING specified system ID
	 */
	public Collection<String> getRelatedDetectionSystems(String detectionSystemId) {
		Collection<String> relatedDetectionSystems = new HashSet<String>();
		
		relatedDetectionSystems.add(detectionSystemId);
	
		if(correlationSets != null) {
			for(CorrelationSet correlationSet : correlationSets) {
				if(correlationSet.getClientApplications() != null) {
					if(correlationSet.getClientApplications().contains(detectionSystemId)) {
						relatedDetectionSystems.addAll(correlationSet.getClientApplications());
					}
				}
			}
		}
		
		return relatedDetectionSystems;
	}
	
	/**
	 * Locate detection point configuration from server-side config file. 
	 * 
	 * @param search detection point that has been added to the system
	 * @return DetectionPoint populated with configuration information from server-side config
	 */
	public DetectionPoint findDetectionPoint(DetectionPoint search) {
		DetectionPoint detectionPoint = null;
		
		detectionPoint = detectionPointCache.get(search.getId());

		if (detectionPoint == null) {
			for (DetectionPoint configuredDetectionPoint : getDetectionPoints()) {
				if (configuredDetectionPoint.getId().equals(search.getId())) {
					detectionPoint = configuredDetectionPoint;
					
					//cache
					detectionPointCache.put(detectionPoint.getId(), detectionPoint);
					
					break;
				}
			}
		}
		
		return detectionPoint;
	}
	
	public ClientApplication findClientApplication(String clientApplicationName) {
		ClientApplication clientApplication = null;
		
		clientApplication = clientApplicationCache.get(clientApplicationName);

		if (clientApplication == null) {
			for (ClientApplication configuredClientApplication : getClientApplications()) {
				if (configuredClientApplication.getName().equals(clientApplicationName)) {
					clientApplication = configuredClientApplication;
					
					//cache
					clientApplicationCache.put(clientApplicationName, clientApplication);
					
					break;
				}
			}
		}
		
		return clientApplication;
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder(17,31).
				append(eventAnalysisEngineImplementation).
				append(attackAnalysisEngineImplementation).
				append(responseAnalysisEngineImplementation).
				append(eventStoreImplementation).
				append(attackStoreImplementation).
				append(responseStoreImplementation).
				append(loggerImplementation).
				append(accessControllerImplementation).
				append(eventStoreObserverImplementations).
				append(attackStoreObserverImplementations).
				append(responseStoreObserverImplementations).
				append(detectionPoints).
				append(correlationSets).
				append(clientApplicationIdentificationHeaderName).
				append(clientApplications).
				toHashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		
		ServerConfiguration other = (ServerConfiguration) obj;
		
		return new EqualsBuilder().
				append(eventAnalysisEngineImplementation, other.getEventAnalysisEngineImplementation()).
				append(attackAnalysisEngineImplementation, other.getAttackAnalysisEngineImplementation()).
				append(responseAnalysisEngineImplementation, other.getResponseAnalysisEngineImplementation()).
				append(eventStoreImplementation, other.getEventStoreImplementation()).
				append(attackStoreImplementation, other.getAttackStoreImplementation()).
				append(responseStoreImplementation, other.getResponseStoreImplementation()).
				append(loggerImplementation, other.getLoggerImplementation()).
				append(accessControllerImplementation, other.getAccessControllerImplementation()).
				append(eventStoreObserverImplementations, other.getEventStoreObserverImplementations()).
				append(attackStoreObserverImplementations, other.getAttackStoreObserverImplementations()).
				append(responseStoreObserverImplementations, other.getResponseStoreObserverImplementations()).
				append(detectionPoints, other.getDetectionPoints()).
				append(correlationSets, other.getCorrelationSets()).
				append(clientApplicationIdentificationHeaderName, other.getClientApplicationIdentificationHeaderName()).
				append(clientApplications, other.getClientApplications()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
				append("eventAnalysisEngineImplementation", eventAnalysisEngineImplementation).
				append("attackAnalysisEngineImplementation", attackAnalysisEngineImplementation).
				append("responseAnalysisEngineImplementation", responseAnalysisEngineImplementation).
				append("eventStoreImplementation", eventStoreImplementation).
				append("attackStoreImplementation", attackStoreImplementation).
				append("responseStoreImplementation", responseStoreImplementation).
				append("loggerImplementation", loggerImplementation).
				append("accessControllerImplementation", accessControllerImplementation).
				append("eventStoreObserverImplementations", eventStoreObserverImplementations).
				append("attackStoreObserverImplementations", attackStoreObserverImplementations).
				append("responseStoreObserverImplementations", responseStoreObserverImplementations).
			    append("detectionPoints", detectionPoints).
			    append("correlationSets", correlationSets).
			    append("clientApplicationIdentificationHeaderName", clientApplicationIdentificationHeaderName).
			    append("clientApplications", clientApplications).
			    toString();
	}

}
