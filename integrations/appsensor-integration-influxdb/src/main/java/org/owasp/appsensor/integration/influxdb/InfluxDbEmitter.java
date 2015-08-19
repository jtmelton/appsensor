package org.owasp.appsensor.integration.influxdb;

import javax.annotation.PostConstruct;
import javax.inject.Named;
import javax.management.InstanceAlreadyExistsException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationListener;
import javax.management.ObjectName;

import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.listener.SystemListener;
import org.owasp.appsensor.core.logging.Loggable;
import org.slf4j.Logger;

import com.google.gson.Gson;

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
	
	@SuppressWarnings("unused")
	private Logger logger;
	
	public InfluxDbEmitter() {}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAdd(Event event) {
		// this is the user that caused the event
		String username = event.getUser().getUsername();
		// ip address of user may or may not exist
		if(event.getUser().getIPAddress() != null) {
			String userIpAddress = event.getUser().getIPAddress().getAddressAsString();
		}
		// timestamp when event occurred
		String timestamp = event.getTimestamp();
		// detection system (what application saw the event)
		String detectionSystem = event.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
		if(event.getDetectionSystem().getIPAddress() != null) {
			String detectionSystemIpAddress = event.getDetectionSystem().getIPAddress().getAddressAsString();
		}
		// category for detection point 
		String category = event.getDetectionPoint().getCategory();
		// label for detection point
		String label = event.getDetectionPoint().getLabel();
		
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
		if(attack.getUser().getIPAddress() != null) {
			String userIpAddress = attack.getUser().getIPAddress().getAddressAsString();
		}
		// timestamp when attack occurred
		String timestamp = attack.getTimestamp();
		// detection system (what application saw the attack)
		String detectionSystem = attack.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
		if(attack.getDetectionSystem().getIPAddress() != null) {
			String detectionSystemIpAddress = attack.getDetectionSystem().getIPAddress().getAddressAsString();
		}
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
		if(response.getUser().getIPAddress() != null) {
			String userIpAddress = response.getUser().getIPAddress().getAddressAsString();
		}
		// timestamp when response was generated
		String timestamp = response.getTimestamp();
		// detection system (what application should perform the response)
		String detectionSystem = response.getDetectionSystem().getDetectionSystemId();
		// detection system ip address may or may not exist
		if(response.getDetectionSystem().getIPAddress() != null) {
			String detectionSystemIpAddress = response.getDetectionSystem().getIPAddress().getAddressAsString();
		}
		// the name of the actual response to execute
		String action = response.getAction();
		// response interval may or may not exist
		if(response.getInterval() != null) {
			// duration for response interval
			int intervalDuration = response.getInterval().getDuration();
			// unit for response interval
			String intervalUnit = response.getInterval().getUnit();
		}
		
		logger.info("received response in influx db emitter at: " + response.getTimestamp());
	}
	
}
