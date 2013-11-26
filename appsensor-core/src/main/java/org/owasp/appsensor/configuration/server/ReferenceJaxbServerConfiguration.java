package org.owasp.appsensor.configuration.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.eclipse.persistence.oxm.annotations.XmlPath;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.correlation.CorrelationSet;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "appsensor-server-config")
public class ReferenceJaxbServerConfiguration implements ServerConfiguration {

	@XmlPath("event-analyzer/@class")
	private String eventAnalysisEngineImplementation;
	@XmlPath("attack-analyzer/@class")
	private String attackAnalysisEngineImplementation;
	@XmlPath("response-analyzer/@class")
	private String responseAnalysisEngineImplementation;
	
	@XmlPath("event-store/@class")
	private String eventStoreImplementation;
	@XmlPath("attack-store/@class")
	private String attackStoreImplementation;
	@XmlPath("response-store/@class")
	private String responseStoreImplementation;
	
	@XmlPath("logger/@class")
	private String loggerImplementation;
	
	@XmlPath("response-handler/@class")
	private String responseHandlerImplementation;
	
	@XmlPath("event-store-observers/observer/@class")
	private Collection<String> eventStoreObserverImplementations;
	@XmlPath("attack-store-observers/observer/@class")
	private Collection<String> attackStoreObserverImplementations;
	@XmlPath("response-store-observers/observer/@class")
	private Collection<String> responseStoreObserverImplementations;
	
	@XmlElementWrapper(name="detection-points")
	@XmlElement(name="detection-point")
	private Collection<DetectionPoint> detectionPoints = new ArrayList<DetectionPoint>(); 
	
	@XmlElementWrapper(name="correlation-config")
	@XmlElement(name="correlated-client-set")
	private Collection<CorrelationSet> correlationSets = new HashSet<CorrelationSet>();
	
	private static transient Map<String, DetectionPoint> detectionPointCache = Collections.synchronizedMap(new HashMap<String, DetectionPoint>());
	
	@Override
	public String getEventAnalysisEngineImplementation() {
		return eventAnalysisEngineImplementation;
	}
	
	@Override
	public ReferenceJaxbServerConfiguration setEventAnalysisEngineImplementation(
			String eventAnalysisEngineImplementation) {
		this.eventAnalysisEngineImplementation = eventAnalysisEngineImplementation;
		return this;
	}

	@Override
	public String getAttackAnalysisEngineImplementation() {
		return attackAnalysisEngineImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setAttackAnalysisEngineImplementation(
			String attackAnalysisEngineImplementation) {
		this.attackAnalysisEngineImplementation = attackAnalysisEngineImplementation;
		return this;
	}

	@Override
	public String getResponseAnalysisEngineImplementation() {
		return responseAnalysisEngineImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setResponseAnalysisEngineImplementation(
			String responseAnalysisEngineImplementation) {
		this.responseAnalysisEngineImplementation = responseAnalysisEngineImplementation;
		return this;
	}

	@Override
	public String getEventStoreImplementation() {
		return eventStoreImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setEventStoreImplementation(String eventStoreImplementation) {
		this.eventStoreImplementation = eventStoreImplementation;
		return this;
	}

	@Override
	public String getAttackStoreImplementation() {
		return attackStoreImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setAttackStoreImplementation(String attackStoreImplementation) {
		this.attackStoreImplementation = attackStoreImplementation;
		return this;
	}

	@Override
	public String getResponseStoreImplementation() {
		return responseStoreImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setResponseStoreImplementation(String responseStoreImplementation) {
		this.responseStoreImplementation = responseStoreImplementation;
		return this;
	}

	@Override
	public String getLoggerImplementation() {
		return loggerImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setLoggerImplementation(String loggerImplementation) {
		this.loggerImplementation = loggerImplementation;
		return this;
	}
	
	@Override
	public String getResponseHandlerImplementation() {
		return responseHandlerImplementation;
	}

	@Override
	public ReferenceJaxbServerConfiguration setResponseHandlerImplementation(String responseHandlerImplementation) {
		this.responseHandlerImplementation = responseHandlerImplementation;
		return this;
	}
	
	@Override
	public Collection<String> getEventStoreObserverImplementations() {
		return eventStoreObserverImplementations;
	}

	@Override
	public ReferenceJaxbServerConfiguration setEventStoreObserverImplementations(
			Collection<String> eventStoreObserverImplementations) {
		this.eventStoreObserverImplementations = eventStoreObserverImplementations;
		return this;
	}

	@Override
	public Collection<String> getAttackStoreObserverImplementations() {
		return attackStoreObserverImplementations;
	}

	@Override
	public ReferenceJaxbServerConfiguration setAttackStoreObserverImplementations(
			Collection<String> attackStoreObserverImplementations) {
		this.attackStoreObserverImplementations = attackStoreObserverImplementations;
		return this;
	}

	@Override
	public Collection<String> getResponseStoreObserverImplementations() {
		return responseStoreObserverImplementations;
	}

	@Override
	public ReferenceJaxbServerConfiguration setResponseStoreObserverImplementations(
			Collection<String> responseStoreObserverImplementations) {
		this.responseStoreObserverImplementations = responseStoreObserverImplementations;
		return this;
	}
	
	@Override
	public Collection<DetectionPoint> getDetectionPoints() {
		return detectionPoints;
	}

	@Override
	public ReferenceJaxbServerConfiguration setDetectionPoints(Collection<DetectionPoint> detectionPoints) {
		this.detectionPoints = detectionPoints;
		return this;
	}
	
	@Override
	public Collection<CorrelationSet> getCorrelationSets() {
		return correlationSets;
	}

	@Override
	public ReferenceJaxbServerConfiguration setCorrelationSets(Collection<CorrelationSet> correlationSets) {
		this.correlationSets = correlationSets;
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
	@Override
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
	@Override
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
				append(responseHandlerImplementation).
				append(eventStoreObserverImplementations).
				append(attackStoreObserverImplementations).
				append(responseStoreObserverImplementations).
				append(detectionPoints).
				append(correlationSets).
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
		
		ReferenceJaxbServerConfiguration other = (ReferenceJaxbServerConfiguration) obj;
		
		return new EqualsBuilder().
				append(eventAnalysisEngineImplementation, other.getEventAnalysisEngineImplementation()).
				append(attackAnalysisEngineImplementation, other.getAttackAnalysisEngineImplementation()).
				append(responseAnalysisEngineImplementation, other.getResponseAnalysisEngineImplementation()).
				append(eventStoreImplementation, other.getEventStoreImplementation()).
				append(attackStoreImplementation, other.getAttackStoreImplementation()).
				append(responseStoreImplementation, other.getResponseStoreImplementation()).
				append(loggerImplementation, other.getLoggerImplementation()).
				append(responseHandlerImplementation, other.getResponseHandlerImplementation()).
				append(eventStoreObserverImplementations, other.getEventStoreObserverImplementations()).
				append(attackStoreObserverImplementations, other.getAttackStoreObserverImplementations()).
				append(responseStoreObserverImplementations, other.getResponseStoreObserverImplementations()).
				append(detectionPoints, other.getDetectionPoints()).
				append(correlationSets, other.getCorrelationSets()).
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
				append("responseHandlerImplementation", responseHandlerImplementation).
				append("eventStoreObserverImplementations", eventStoreObserverImplementations).
				append("attackStoreObserverImplementations", attackStoreObserverImplementations).
				append("responseStoreObserverImplementations", responseStoreObserverImplementations).
			    append("detectionPoints", detectionPoints).
			    append("correlationSets", correlationSets).
			    toString();
	}
	
}
