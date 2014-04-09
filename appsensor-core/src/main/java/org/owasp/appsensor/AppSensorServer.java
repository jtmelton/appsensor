package org.owasp.appsensor;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.accesscontrol.AccessController;
import org.owasp.appsensor.analysis.AnalysisEngine;
import org.owasp.appsensor.correlation.CorrelationSet;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.storage.AttackStore;
import org.owasp.appsensor.storage.EventStore;
import org.owasp.appsensor.storage.ResponseStore;
import org.slf4j.Logger;

/**
 * AppSensor locator class is provided to make it easy to gain access to the 
 * AppSensor classes in use. Use the set methods to override the reference 
 * implementations with instances of any custom implementations.  Alternatively, 
 * These configurations are set in the appsensor-server-config.xml file.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
@Loggable
public class AppSensorServer {
	
	/** accessor for {@link org.owasp.appsensor.storage.EventStore} */
	private EventStore eventStore;
	
	/** accessor for {@link org.owasp.appsensor.storage.AttackStore} */
	private AttackStore attackStore;
	
	/** accessor for {@link org.owasp.appsensor.storage.ResponseStore} */
	private ResponseStore responseStore;
	
	/** accessor for Event {@link org.owasp.appsensor.storage.AnalysisEngine} */
	private AnalysisEngine eventAnalysisEngine;
	
	/** accessor for Attack {@link org.owasp.appsensor.storage.AnalysisEngine} */
	private AnalysisEngine attackAnalysisEngine;
	
	/** accessor for Response {@link org.owasp.appsensor.storage.AnalysisEngine} */
	private AnalysisEngine responseAnalysisEngine;
	
	/** accessor for {@link org.owasp.appsensor.accesscontrol.AccessController} */
	private AccessController accessController;
	
	private Logger logger;
	
	private Collection<CorrelationSet> correlationSets = new HashSet<>();
	
	private String clientApplicationIdentificationHeaderName;
	
	private Map<String, DetectionPoint> detectionPoints = Collections.synchronizedMap(new HashMap<String, DetectionPoint>());

	private Map<String, ClientApplication> clientApplications = Collections.synchronizedMap(new HashMap<String, ClientApplication>());
	
	public String getClientApplicationIdentificationHeaderName() {
		return clientApplicationIdentificationHeaderName;
	}

	public void setClientApplicationIdentificationHeaderName(
			String clientApplicationIdentificationHeaderName) {
		this.clientApplicationIdentificationHeaderName = clientApplicationIdentificationHeaderName;
	}

	public Collection<DetectionPoint> getDetectionPoints() {
		return detectionPoints.values();
	}

	public DetectionPoint findDetectionPoint(String detectionPointId) {
		return detectionPoints != null ? detectionPoints.get(detectionPointId) : null;
	}

	public ClientApplication findClientApplication(String search) {
		return clientApplications != null ? clientApplications.get(search) : null;
	}
	
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

	private AppSensorServer() { }
	
	/**
	 * Accessor for Event AnalysisEngine object
	 * @return Event AnalysisEngine object
	 */
	public AnalysisEngine getEventAnalysisEngine() {
		return eventAnalysisEngine;
	}
	
	/**
	 * Accessor for Attack AnalysisEngine object
	 * @return Attack AnalysisEngine object
	 */
	public AnalysisEngine getAttackAnalysisEngine() {
		return attackAnalysisEngine;
	}
	
	/**
	 * Accessor for Response AnalysisEngine object
	 * @return Response AnalysisEngine object
	 */
	public AnalysisEngine getResponseAnalysisEngine() {
		return responseAnalysisEngine;
	}
	
	/**
	 * Accessor for EventStore object
	 * @return EventStore object
	 */
	public EventStore getEventStore() {
		return eventStore; 
	}
	
	/**
	 * Accessor for AttackStore object
	 * @return AttackStore object
	 */
	public AttackStore getAttackStore() {
		return attackStore;
	}
	
	/**
	 * Accessor for ResponseStore object
	 * @return ResponseStore object
	 */
	public ResponseStore getResponseStore() {
		return responseStore;
	}
	
	/**
	 * Accessor for Logger object
	 * @return Logger object
	 */
	public Logger getLogger() {
		return logger;
	}
	
	/**
	 * Accessor for AccessController object. 
	 * @return AccessController object
	 */
	public AccessController getAccessController() {
		return accessController;
	}
	
	public void setDetectionPoints(Collection<DetectionPoint> detectionPoints) {
		Map<String, DetectionPoint> mappedDetectionPoints = Collections.synchronizedMap(new HashMap<String, DetectionPoint>());
		for (DetectionPoint detectionPoint : detectionPoints == null ? Collections.<DetectionPoint>emptyList() : detectionPoints) {
			mappedDetectionPoints.put(detectionPoint.getId(), detectionPoint);
		}
		this.detectionPoints = mappedDetectionPoints;
	}

	@Inject
	public void setEventStore(EventStore eventStore) {
		this.eventStore = eventStore;
	}

	@Inject
	public void setAttackStore(AttackStore attackStore) {
		this.attackStore = attackStore;
	}

	@Inject
	public void setResponseStore(ResponseStore responseStore) {
		this.responseStore = responseStore;
	}

	@Inject @Named("EventAnalysisEngine")
	public void setEventAnalysisEngine(AnalysisEngine eventAnalysisEngine) {
		this.eventAnalysisEngine = eventAnalysisEngine;
	}

	@Inject @Named("AttackAnalysisEngine")
	public void setAttackAnalysisEngine(AnalysisEngine attackAnalysisEngine) {
		this.attackAnalysisEngine = attackAnalysisEngine;
	}

	@Inject
	public void setAccessController(AccessController accessController) {
		this.accessController = accessController;
	}
}
