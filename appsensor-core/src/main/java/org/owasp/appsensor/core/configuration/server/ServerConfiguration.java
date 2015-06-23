package org.owasp.appsensor.core.configuration.server;

import java.io.File;
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
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.correlation.CorrelationSet;

/**
 * Represents the configuration for server-side components. Additionally, 
 * contains various helper methods for common configuration-related 
 * actions.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public abstract class ServerConfiguration {
	
	private transient File configurationFile;
	
	private Collection<DetectionPoint> detectionPoints = new ArrayList<>(); 
	
	private Collection<CorrelationSet> correlationSets = new HashSet<>();
	
	private String clientApplicationIdentificationHeaderName;
	
	private Collection<ClientApplication> clientApplications = new HashSet<>();
	
	private String serverHostName;
	
	private int serverPort;
	
	private int serverSocketTimeout;
	
	private boolean geolocateIpAddresses = false;
	
	private String geolocationDatabasePath;
	
	private static transient Map<String, ClientApplication> clientApplicationCache = Collections.synchronizedMap(new HashMap<String, ClientApplication>());
	
	public File getConfigurationFile() {
		return configurationFile;
	}

	public ServerConfiguration setConfigurationFile(File configurationFile) {
		this.configurationFile = configurationFile;
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

	public String getServerHostName() {
		return serverHostName;
	}

	public ServerConfiguration setServerHostName(String serverHostName) {
		this.serverHostName = serverHostName;
		
		return this;
	}

	public int getServerPort() {
		return serverPort;
	}

	public ServerConfiguration setServerPort(int serverPort) {
		this.serverPort = serverPort;
		
		return this;
	}

	public int getServerSocketTimeout() {
		return serverSocketTimeout;
	}

	public ServerConfiguration setServerSocketTimeout(int serverSocketTimeout) {
		this.serverSocketTimeout = serverSocketTimeout;
		
		return this;
	}

	public boolean isGeolocateIpAddresses() {
		return geolocateIpAddresses;
	}

	public ServerConfiguration setGeolocateIpAddresses(boolean geolocateIpAddresses) {
		this.geolocateIpAddresses = geolocateIpAddresses;
		
		return this;
	}
	
	public String getGeolocationDatabasePath() {
		return geolocationDatabasePath;
	}

	public ServerConfiguration setGeolocationDatabasePath(String geolocationDatabasePath) {
		this.geolocationDatabasePath = geolocationDatabasePath;
		
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
	public Collection<String> getRelatedDetectionSystems(DetectionSystem detectionSystem) {
		Collection<String> relatedDetectionSystems = new HashSet<String>();
		
		relatedDetectionSystems.add(detectionSystem.getDetectionSystemId());
	
		if(correlationSets != null) {
			for(CorrelationSet correlationSet : correlationSets) {
				if(correlationSet.getClientApplications() != null) {
					if(correlationSet.getClientApplications().contains(detectionSystem.getDetectionSystemId())) {
						relatedDetectionSystems.addAll(correlationSet.getClientApplications());
					}
				}
			}
		}
		
		return relatedDetectionSystems;
	}
	
	/**
	 * Locate matching detection points configuration from server-side config file. 
	 * 
	 * @param search detection point that has been added to the system
	 * @return DetectionPoint populated with configuration information from server-side config
	 */
	public Collection<DetectionPoint> findDetectionPoints(DetectionPoint search) {
		Collection<DetectionPoint> matches = new ArrayList<>();
		
		for (DetectionPoint configuredDetectionPoint : getDetectionPoints()) {
			if (configuredDetectionPoint.typeMatches(search)) {
				matches.add(configuredDetectionPoint);
			}
		}
		
		return matches;
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
				append(serverHostName).
				append(serverPort).
				append(serverSocketTimeout).
				append(geolocateIpAddresses).
				append(geolocationDatabasePath).
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
				append(serverHostName, other.getServerHostName()).
				append(serverPort, other.getServerPort()).
				append(serverSocketTimeout, other.getServerSocketTimeout()).
				append(geolocateIpAddresses, other.isGeolocateIpAddresses()).
				append(geolocationDatabasePath, other.getGeolocationDatabasePath()).
				isEquals();
	}
	
	@Override
	public String toString() {
		return new ToStringBuilder(this).
			    append("detectionPoints", detectionPoints).
			    append("correlationSets", correlationSets).
			    append("clientApplicationIdentificationHeaderName", clientApplicationIdentificationHeaderName).
			    append("clientApplications", clientApplications).
			    append("serverHostName", serverHostName).
			    append("serverPort", serverPort).
			    append("serverSocketTimeout", serverSocketTimeout).
			    append("geolocateIpAddresses", geolocateIpAddresses).
			    append("geolocationDatabasePath", geolocationDatabasePath).
			    toString();
	}

}
