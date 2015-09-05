package org.owasp.appsensor.integration.influxdb;

import java.util.ArrayList;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.StringUtils;
import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;

/**
 * This is the Influxdb Emitter. 
 * 
 * It is notified whenever new {@link Event}, {@link Attack} 
 * or {@link Response} objects are added to the system. 
 * 
 * The implementation sends events/attacks/responses to 
 * influx every time they are received. 
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.2
 * 
 */

/**
 * This is the Influxdb Emitter. 
 * 
 * It is notified whenever new {@link Event}, {@link Attack} 
 * or {@link Response} objects are added to the system. 
 * 
 * The implementation sends events/attacks/responses to 
 * influx every time they are received.
 * 
 * <p>This implementation uses some standard configuration settings: </p> 
 * <p>The database is named "appsensor". (Note: this must exist beforehand)</p>
 * <p>There are 3 measurements produced:</p>
 * <p>The measurement for events is named "appsensor_events"</p>
 * <p>The measurement for attacks is named "appsensor_attacks"</p>
 * <p>The measurement for responses is named "appsensor_responses"</p>
 * 
 * <p>Note: This class requires a few settings to run properly. These can be set as either
 *    environment variables ('export my_var="some_value"') or environment 
 *    properties ('-Dmy_var=some_value') set at the JVM</p>
 * <ul>
 *   <li><em>APPSENSOR_INFLUXDB_URL</em> - the url used to connect to influxdb, e.g. "http://1.2.3.4:8086"</li>
 *   <li><em>APPSENSOR_INFLUXDB_USERNAME</em> - the username used to connect to influxdb, e.g. "my_username"</li>
 *   <li><em>APPSENSOR_INFLUXDB_PASSWORD</em> - the password used to connect to influxdb, e.g. "my_password"</li>
 * </ul>
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * 
 * @since 2.2
 */
@Named
public class InfluxDbEmitter extends SystemListener {
	
	private boolean initializedProperly = false;
	
	private static final String DB = "appsensor";
	private static final String EVENTS = "appsensor_events";
	private static final String ATTACKS = "appsensor_attacks";
	private static final String RESPONSES = "appsensor_responses";
	
	public static final String INFLUXDB_URL = "APPSENSOR_INFLUXDB_URL";
	public static final String INFLUXDB_USERNAME = "APPSENSOR_INFLUXDB_USERNAME";
	public static final String INFLUXDB_PASSWORD = "APPSENSOR_INFLUXDB_PASSWORD";

	private InfluxDB db;
	
	private String url;
	private String username;
	private String password;
	
	private Logger logger = LoggerFactory.getLogger(getClass());
	
	@Inject
	private Environment environment;
	
	public InfluxDbEmitter() {}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		ensureInitialized();
		
		// this is the user that caused the event
		String username = event.getUser().getUsername();
		// ip address of user may or may not exist
//		if(event.getUser().getIPAddress() != null) {
//			String userIpAddress = event.getUser().getIPAddress().getAddressAsString();
//		}
		// timestamp when event occurred
		String timestamp = event.getTimestamp();
		// detection system (what application saw the event)
		String detectionSystem = event.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
//		if(event.getDetectionSystem().getIPAddress() != null) {
//			String detectionSystemIpAddress = event.getDetectionSystem().getIPAddress().getAddressAsString();
//		}
		// category for detection point 
		String category = event.getDetectionPoint().getCategory();
		// label for detection point
		String label = event.getDetectionPoint().getLabel();
		
		Point point = Point.measurement(EVENTS)
				.time(DateUtils.fromString(timestamp).getMillis(), TimeUnit.MILLISECONDS)
				.field("label", label)
				.tag("username",username)
				.tag("timestamp",timestamp)
				.tag("detectionSystem",detectionSystem)
				.tag("category",category)
				.tag("label",label)
                .build();
		
		db.write(DB, "default", point);
		
		logger.info("received event in influx db emitter at: " + event.getTimestamp());
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
		
		Point point = Point.measurement(ATTACKS)
				.time(DateUtils.fromString(timestamp).getMillis(), TimeUnit.MILLISECONDS)
				.field("label", label)
				.tag("username",username)
				.tag("timestamp",timestamp)
				.tag("detectionSystem",detectionSystem)
				.tag("category",category)
				.tag("label",label)
				.tag("thresholdCount",String.valueOf(thresholdCount))
				.tag("thresholdIntervalDuration",String.valueOf(thresholdIntervalDuration))
				.tag("thresholdIntervalUnit",thresholdIntervalUnit)
                .build();
		
		db.write(DB, "default", point);
		
		logger.info("received attack in influx db emitter at: " + attack.getTimestamp());
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
		
		Point point = Point.measurement(RESPONSES)
				.time(DateUtils.fromString(timestamp).getMillis(), TimeUnit.MILLISECONDS)
				.field("action", action)
				.tag("username",username)
				.tag("timestamp",timestamp)
				.tag("detectionSystem",detectionSystem)
				.tag("action",action)
                .build();
		
		db.write(DB, "default", point);
		
		logger.info("received response in influx db emitter at: " + response.getTimestamp());
	}
	
	@PostConstruct
	public void ensureEnvironmentVariablesSet() {
		initializedProperly = isInitializedProperly();

		if (! initializedProperly) {
			logger.error(getUninitializedMessage());
		} else {
			initializeConfig();
			initializeDb();
		}
	}
	
	private void ensureInitialized() {
		if(! initializedProperly) {
			throw new IllegalStateException(getUninitializedMessage());
		}
	}
	
	private void initializeConfig() {
		url = environment.getProperty(INFLUXDB_URL);
		username = environment.getProperty(INFLUXDB_USERNAME);
		password = environment.getProperty(INFLUXDB_PASSWORD);
	}
	
	private void initializeDb() {
		db = InfluxDBFactory.connect(url, username, password);
	}
	
	private boolean isInitializedProperly() {
		boolean initializedProperly = false;
		
		initializedProperly = StringUtils.isNotBlank(environment.getProperty(INFLUXDB_URL)) &&
				StringUtils.isNotBlank(environment.getProperty(INFLUXDB_USERNAME)) &&
				StringUtils.isNotBlank(environment.getProperty(INFLUXDB_PASSWORD));

		return initializedProperly;
	}
	
	private String getUninitializedMessage() {
		StringBuilder sb = new StringBuilder();
		
		Collection<String> setVariables = new ArrayList<>();
		Collection<String> missingVariables = new ArrayList<>();
		
		if (StringUtils.isBlank(environment.getProperty(INFLUXDB_URL))) {
			missingVariables.add(INFLUXDB_URL);
		} else {
			setVariables.add(INFLUXDB_URL);
		}
		
		if (StringUtils.isBlank(environment.getProperty(INFLUXDB_USERNAME))) {
			missingVariables.add(INFLUXDB_USERNAME);
		} else {
			setVariables.add(INFLUXDB_USERNAME);
		}
		
		if (StringUtils.isBlank(environment.getProperty(INFLUXDB_PASSWORD))) {
			missingVariables.add(INFLUXDB_PASSWORD);
		} else {
			setVariables.add(INFLUXDB_PASSWORD);
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
