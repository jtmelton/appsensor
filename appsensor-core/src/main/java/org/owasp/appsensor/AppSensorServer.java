package org.owasp.appsensor;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.accesscontrol.AccessController;
import org.owasp.appsensor.analysis.AttackAnalysisEngine;
import org.owasp.appsensor.analysis.EventAnalysisEngine;
import org.owasp.appsensor.analysis.ResponseAnalysisEngine;
import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.logging.Loggable;
import org.owasp.appsensor.storage.AttackStore;
import org.owasp.appsensor.storage.EventStore;
import org.owasp.appsensor.storage.ResponseStore;
import org.slf4j.Logger;

/**
 * AppSensor core class for accessing server-side components. Most components
 * are discoverd via DI. However, the configuration portions are setup in 
 * the appsensor-server-config.xml file.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@Named
@Loggable
public class AppSensorServer {
	
	@SuppressWarnings("unused")
	private Logger logger;
	
	/** accessor for {@link org.owasp.appsensor.configuration.server.ServerConfiguration} */
	private ServerConfiguration configuration;
	
	/** accessor for {@link org.owasp.appsensor.storage.EventStore} */
	private EventStore eventStore;
	
	/** accessor for {@link org.owasp.appsensor.storage.AttackStore} */
	private AttackStore attackStore;
	
	/** accessor for {@link org.owasp.appsensor.storage.ResponseStore} */
	private ResponseStore responseStore;
	
	/** accessor for {@link org.owasp.appsensor.storage.EventAnalysisEngine} */
	private EventAnalysisEngine eventAnalysisEngine;
	
	/** accessor for {@link org.owasp.appsensor.storage.AttackAnalysisEngine} */
	private AttackAnalysisEngine attackAnalysisEngine;
	
	/** accessor for {@link org.owasp.appsensor.storage.ResponseAnalysisEngine} */
	private ResponseAnalysisEngine responseAnalysisEngine;
	
	/** accessor for {@link org.owasp.appsensor.accesscontrol.AccessController} */
	private AccessController accessController;
	
	public AppSensorServer() { }
	
	/**
	 * Accessor for ServerConfiguration object
	 * @return ServerConfiguration object
	 */
	public ServerConfiguration getConfiguration() {
		return configuration;
	}
	
	@Inject
	public void setConfiguration(ServerConfiguration updatedConfiguration) {
		configuration = updatedConfiguration;
	}
	
	public EventStore getEventStore() {
		return eventStore;
	}

	public AttackStore getAttackStore() {
		return attackStore;
	}

	public ResponseStore getResponseStore() {
		return responseStore;
	}

	public EventAnalysisEngine getEventAnalysisEngine() {
		return eventAnalysisEngine;
	}

	public AttackAnalysisEngine getAttackAnalysisEngine() {
		return attackAnalysisEngine;
	}
	
	public ResponseAnalysisEngine getResponseAnalysisEngine() {
		return responseAnalysisEngine;
	}

	public AccessController getAccessController() {
		return accessController;
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

	@Inject
	public void setEventAnalysisEngine(EventAnalysisEngine eventAnalysisEngine) {
		this.eventAnalysisEngine = eventAnalysisEngine;
	}

	@Inject
	public void setAttackAnalysisEngine(AttackAnalysisEngine attackAnalysisEngine) {
		this.attackAnalysisEngine = attackAnalysisEngine;
	}

	@Inject
	public void setResponseAnalysisEngine(ResponseAnalysisEngine responseAnalysisEngine) {
		this.responseAnalysisEngine = responseAnalysisEngine;
	}
	
	@Inject
	public void setAccessController(AccessController accessController) {
		this.accessController = accessController;
	}
	
}
