package org.owasp.appsensor.core.configuration.server;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.owasp.appsensor.core.ClientApplication;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.correlation.CorrelationSet;

/**
 * Represents the configuration for server-side components. Additionally, 
 * contains various helper methods for common configuration-related 
 * actions.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public abstract class ServerConfiguration {
	
	private Collection<DetectionPoint> detectionPoints = new ArrayList<>(); 
	
	private Collection<CorrelationSet> correlationSets = new HashSet<>();
	
	private String clientApplicationIdentificationHeaderName;
	
	private Collection<ClientApplication> clientApplications = new HashSet<>();
	
	private static transient Map<String, DetectionPoint> detectionPointCache = Collections.synchronizedMap(new HashMap<String, DetectionPoint>());
	
	private static transient Map<String, ClientApplication> clientApplicationCache = Collections.synchronizedMap(new HashMap<String, ClientApplication>());
	
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
		
		detectionPoint = detectionPointCache.get(search.getLabel());

		if (detectionPoint == null) {
			for (DetectionPoint configuredDetectionPoint : getDetectionPoints()) {
				if (configuredDetectionPoint.typeMatches(search)) {
					detectionPoint = configuredDetectionPoint;
					
					//cache
					detectionPointCache.put(detectionPoint.getLabel(), detectionPoint);
					
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
				append(detectionPoints, other.getDetectionPoints()).
				append(correlationSets, other.getCorrelationSets()).
				append(clientApplicationIdentificationHeaderName, other.getClientApplicationIdentificationHeaderName()).
				append(clientApplications, other.getClientApplications()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			    append("detectionPoints", detectionPoints).
			    append("correlationSets", correlationSets).
			    append("clientApplicationIdentificationHeaderName", clientApplicationIdentificationHeaderName).
			    append("clientApplications", clientApplications).
			    toString();
	}

}
