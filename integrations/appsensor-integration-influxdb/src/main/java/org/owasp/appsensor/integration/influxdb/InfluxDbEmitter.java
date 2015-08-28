package org.owasp.appsensor.integration.influxdb;

import java.util.concurrent.TimeUnit;

import javax.inject.Named;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.owasp.appsensor.core.util.DateUtils;
import org.slf4j.Logger;

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
@Named
@Loggable
public class InfluxDbEmitter extends SystemListener {
	
	private Logger logger;
	
	public InfluxDbEmitter() {}

	private  InfluxDB db = InfluxDBFactory.connect("http://127.0.0.1:8086", "root", "root");
	
	private static final String DB = "appsensor";
	private static final String EVENTS = "appsensor_events";
	private static final String ATTACKS = "appsensor_attacks";
	private static final String RESPONSES = "appsensor_responses";
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
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
	
}
