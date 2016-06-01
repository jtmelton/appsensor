package org.owasp.appsensor.integration.prometheus;

import io.prometheus.client.exporter.PushGateway;
import org.apache.commons.lang3.StringUtils;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.storage.ResponseStoreListener;
import org.owasp.appsensor.integration.prometheus.metrics.AbstractMetrics;
import org.owasp.appsensor.integration.prometheus.metrics.AttackMetrics;
import org.owasp.appsensor.integration.prometheus.metrics.EventMetrics;
import org.owasp.appsensor.integration.prometheus.metrics.ResponseMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

/**
 * This is the Prometheus Pushgateway Emitter.
 *
 * It is notified whenever new {@link Event}, {@link Attack}
 * or {@link Response} objects are added to the system.
 *
 * The implementation sends events/attacks/responses metrics to
 * pushgateway every time they are received.
 *
 * <p>Note: This class requires certain settings to run properly. This/these can be set as
 *    environment variables ('export my_var="some_value"') or environment
 *    properties ('-Dmy_var=some_value') set at the JVM</p>
 * <ul>
 *   <li><em>PROMETHEUS_PUSHGATEWAY_ADDRESS</em> - the address used to the Prometheus pushgateway, e.g. "127.0.0.1:9091/"</li>
 * </ul>
 *
 * @author Robert Przystasz  (robert.przystasz@gmail.com)
 * @author Bartosz Wyględacz (bartosz.wygledacz@gmail.com)
 * @author Michal Warzecha   (mwarzechaa@gmail.com)
 * @author Magdalena Idzik   (maddie@pwnag3.net)
 *
 * @since 2.2.1
 *
 */

@Named
@ResponseStoreListener
public class PrometheusEmitter extends SystemListener {
	
	private boolean initializedProperly = false;
	
	public static final String PROMETHEUS_PUSHGATEWAY_ADDRESS = "PROMETHEUS_PUSHGATEWAY_ADDRESS";
	private static final String DISABLE_COMPONENT_FOR_ONE_USER = "disableComponentForSpecificUser";
	private static final String DISABLE_COMPONENT_FOR_ALL_USERS = "disableComponentForAllUsers";

	private Collection<String> disableResponseActions = Arrays.asList(DISABLE_COMPONENT_FOR_ONE_USER, DISABLE_COMPONENT_FOR_ALL_USERS);
	
	private String prometheusPushgatewayUrl;
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Inject
	private Environment environment;

	@Inject
	private EventMetrics eventMetrics;

	@Inject
	private AttackMetrics attackMetrics;

	@Inject
	private ResponseMetrics responseMetrics;

	private PushGateway pushGateway;


	@Override
	public void onAdd(Event event) {
		ensureInitialized();

		// this is the user that caused the event
		String username = event.getUser().getUsername();
		// timestamp when event occurred
		String timestamp = event.getTimestamp();
		// detection system (what application saw the event)
		String detectionSystem = event.getDetectionSystem().getDetectionSystemId();
		// category for detection point
		String category = event.getDetectionPoint().getCategory();
		// label for detection point
		String label = event.getDetectionPoint().getLabel();

		eventMetrics.inc(detectionSystem, category, label, username);
		postMetrics(eventMetrics);
		logger.info("received event in prometheus gateway emitter at: " + event.getTimestamp());
	}

	private void postMetrics(AbstractMetrics abstractMetrics) {
		try {
			pushGateway.pushAdd(abstractMetrics.getCollector(), "appsensor");
		} catch(Exception e) {
			logger.error("Error sending metrics to pushgateway.", e);
		}
	}


	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Attack attack) {
		ensureInitialized();

		// this is the user that caused the attack
		String username = attack.getUser().getUsername();
		// ip address of user may or may not exist
//		if(attack.getUser().getIPAddress() != null) {
//			String userIpAddress = attack.getUser().getIPAddress().getAddressAsString();
//		}
		// timestamp when attack occurred
		String timestamp = attack.getTimestamp();
		// detection system (what application saw the attack)
		String detectionSystem = attack.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
//		if(attack.getDetectionSystem().getIPAddress() != null) {
//			String detectionSystemIpAddress = attack.getDetectionSystem().getIPAddress().getAddressAsString();
//		}
		// category for detection point
		String category = attack.getDetectionPoint().getCategory();
		// label for detection point
		String label = attack.getDetectionPoint().getLabel();
		// count for detection point threshold
		int thresholdCount = attack.getDetectionPoint().getThreshold().getCount();
		// duration for detection point threshold interval
		int thresholdIntervalDuration = attack.getDetectionPoint().getThreshold().getInterval().getDuration();
		// unit for detection point threshold interval
		String thresholdIntervalUnit = attack.getDetectionPoint().getThreshold().getInterval().getUnit();

		attackMetrics.inc(detectionSystem, category, label, username);
		postMetrics(attackMetrics);
		logger.info("received attack in prometheus gateway emitter at: " + attack.getTimestamp());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Response response) {
		ensureInitialized();

		// this is the user that the response should be executed on
		String username = response.getUser().getUsername();
		// ip address of user may or may not exist
//		if(response.getUser().getIPAddress() != null) {
//			String userIpAddress = response.getUser().getIPAddress().getAddressAsString();
//		}
		// timestamp when response was generated
		String timestamp = response.getTimestamp();
		// detection system (what application should perform the response)
		String detectionSystem = response.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
//		if(response.getDetectionSystem().getIPAddress() != null) {
//			String detectionSystemIpAddress = response.getDetectionSystem().getIPAddress().getAddressAsString();
//		}
		// the name of the actual response to execute
		String action = response.getAction();
		// response interval may or may not exist
//		if(response.getInterval() != null) {
//			// duration for response interval
//			int intervalDuration = response.getInterval().getDuration();
//			// unit for response interval
//			String intervalUnit = response.getInterval().getUnit();
//		}

		responseMetrics.inc(detectionSystem, "test", "test", username);
		postMetrics(responseMetrics);
		logger.info("received response in prometheus gateway emitter at: " + response.getTimestamp());
	}
	
	@PostConstruct
	public void ensureEnvironmentVariablesSet() {
		initializedProperly = isInitializedProperly();

		if (! initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			initializeConfig();
			initializePushGateway();
		}
	}
	
	private void ensureInitialized() {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
	}
	
	private void initializeConfig() {
		prometheusPushgatewayUrl = environment.getProperty(PROMETHEUS_PUSHGATEWAY_ADDRESS);
	}
	
	private void initializePushGateway() {
		pushGateway = new PushGateway(prometheusPushgatewayUrl);
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(PROMETHEUS_PUSHGATEWAY_ADDRESS));
	}
	
	private String getUninitializedMessage() {
		StringBuilder sb = new StringBuilder();
		
		Collection<String> setVariables = new ArrayList<>();
		Collection<String> missingVariables = new ArrayList<>();
		
		if (StringUtils.isBlank(environment.getProperty(PROMETHEUS_PUSHGATEWAY_ADDRESS))) {
			missingVariables.add(PROMETHEUS_PUSHGATEWAY_ADDRESS);
		} else {
			setVariables.add(PROMETHEUS_PUSHGATEWAY_ADDRESS);
		}
		
		if (missingVariables.size() > 0) {
			sb.append("The following Environment variables must be set: ").append(missingVariables);
			
			if (setVariables.size() > 0) {
				sb.append(" (already set variables - ").append(setVariables).append(")");
			}
		}
		
		return sb.toString();
	}
}
