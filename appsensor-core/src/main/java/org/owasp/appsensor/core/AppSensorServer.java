package org.owasp.appsensor.core;

import org.owasp.appsensor.core.accesscontrol.AccessController;
import org.owasp.appsensor.core.analysis.AttackAnalysisEngine;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.analysis.ResponseAnalysisEngine;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.storage.AttackStore;
import org.owasp.appsensor.core.storage.EventStore;
import org.owasp.appsensor.core.storage.ResponseStore;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Collection;

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
	
	/** accessor for {@link org.owasp.appsensor.core.configuration.server.ServerConfiguration} */
	private ServerConfiguration configuration;
	
	/** accessor for {@link org.owasp.appsensor.core.storage.EventStore} */
	private EventStore eventStore;
	
	/** accessor for {@link org.owasp.appsensor.core.storage.AttackStore} */
	private AttackStore attackStore;
	
	/** accessor for {@link org.owasp.appsensor.core.storage.ResponseStore} */
	private ResponseStore responseStore;
	
	/** accessor for {@link org.owasp.appsensor.core.analysis.EventAnalysisEngine} */
	private Collection<EventAnalysisEngine> eventAnalysisEngines;
	
	/** accessor for {@link org.owasp.appsensor.core.analysis.AttackAnalysisEngine} */
	private Collection<AttackAnalysisEngine> attackAnalysisEngines;
	
	/** accessor for {@link org.owasp.appsensor.core.analysis.ResponseAnalysisEngine} */
	private Collection<ResponseAnalysisEngine> responseAnalysisEngines;
	
	/** accessor for {@link org.owasp.appsensor.core.accesscontrol.AccessController} */
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

	public Collection<EventAnalysisEngine> getEventAnalysisEngines() {
		return eventAnalysisEngines;
	}

	public Collection<AttackAnalysisEngine> getAttackAnalysisEngines() {
		return attackAnalysisEngines;
	}
	
	public Collection<ResponseAnalysisEngine> getResponseAnalysisEngines() {
		return responseAnalysisEngines;
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
	public void setEventAnalysisEngines(Collection<EventAnalysisEngine> eventAnalysisEngines) {
		this.eventAnalysisEngines = eventAnalysisEngines;
	}

	@Inject
	public void setAttackAnalysisEngines(Collection<AttackAnalysisEngine> attackAnalysisEngines) {
		this.attackAnalysisEngines = attackAnalysisEngines;
	}

	@Inject
	public void setResponseAnalysisEngines(Collection<ResponseAnalysisEngine> responseAnalysisEngines) {
		this.responseAnalysisEngines = responseAnalysisEngines;
	}
	
	@Inject
	public void setAccessController(AccessController accessController) {
		this.accessController = accessController;
	}
	
}
