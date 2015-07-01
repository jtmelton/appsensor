package org.owasp.appsensor.generator;

import java.util.Random;

import javax.inject.Named;

import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.IPAddress;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.configuration.client.ClientConfiguration;
import org.owasp.appsensor.core.geolocation.GeoLocation;
import org.owasp.appsensor.event.RestEventManager;
import org.springframework.beans.factory.annotation.Autowired;

import com.google.gson.Gson;

@Named
public class GeoDataGenerator {
	
	private Gson gson = new Gson();
	
	// west us - 37.596758, -121.647992
	private User frank = new User("frank", new IPAddress("10.10.10.1", new GeoLocation(37.596758, -121.647992)));
	// australia - -23.342331, 117.810003
	private User susan = new User("susan", new IPAddress("10.10.10.2", new GeoLocation(-23.342331, 117.810003)));
	// morocco - 29.668890, -8.576706
	private User stephen = new User("stephen", new IPAddress("10.10.10.3", new GeoLocation(29.668890, -8.576706)));
	// south africa - -25.423505, 27.106885
	private User cherie = new User("cherie", new IPAddress("10.10.10.4", new GeoLocation(-25.423505, 27.106885)));
	
	private User[] users = new User[] {frank, susan, stephen, cherie};
	
	// 5 in 20 seconds (1 every 4 seconds is an attack)
	private DetectionPoint ie1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1");
	// 6 in 30 seconds (1 every 5 seconds is an attack)
	private DetectionPoint ie2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2");
	// 7 in 40 seconds (1 every 5.7 seconds is an attack)
	private DetectionPoint re3 = new DetectionPoint(DetectionPoint.Category.REQUEST, "RE3");
	// 8 in 50 seconds (1 every 6.25 seconds is an attack)
	private DetectionPoint ae4 = new DetectionPoint(DetectionPoint.Category.AUTHENTICATION, "AE4");

	// GEO DATA IGNORED B/C MAPPING BY REST SERVER
	// ireland - 52.629678, -7.873585
	private DetectionSystem myclientgeoapp1 = new DetectionSystem("myclientgeoapp1", new IPAddress("10.10.10.5", new GeoLocation(52.629678, -7.873585)));
	// brazil - -7.471493, -47.248578
	private DetectionSystem myclientgeoapp2 = new DetectionSystem("myclientgeoapp2", new IPAddress("10.10.10.6", new GeoLocation(-7.471493, -47.248578)));
	// russia - 59.164625, 123.96234
	private DetectionSystem myclientgeoapp3 = new DetectionSystem("myclientgeoapp3", new IPAddress("10.10.10.7", new GeoLocation(59.164625, 123.96234)));
	// india - 12.875989, 77.556100
	private DetectionSystem myclientgeoapp4 = new DetectionSystem("myclientgeoapp4", new IPAddress("10.10.10.8", new GeoLocation(12.875989, 77.556100)));
	
	private DetectionSystem[] detectionSystems = new DetectionSystem[] {myclientgeoapp1, myclientgeoapp2, myclientgeoapp3, myclientgeoapp4};
	
	@Autowired
	RestEventManager eventManager;
	
	@Autowired
	ClientConfiguration configuration;
	
	public void execute() {
		
		EventEmitter ie1Emitter = new EventEmitter(ie1, 1, 4);
		EventEmitter ie2Emitter = new EventEmitter(ie2, 2, 8);
		EventEmitter re3Emitter = new EventEmitter(re3, 3, 5);
		EventEmitter ae4Emitter = new EventEmitter(ae4, 5, 10);
		
		new Thread(ie1Emitter).start();
		new Thread(ie2Emitter).start();
		new Thread(re3Emitter).start();
		new Thread(ae4Emitter).start();
    }
	
	class EventEmitter implements Runnable {

		private DetectionPoint detectionPoint;
		private int lowerBoundSeconds;
		private int upperBoundSeconds;
		
		Random random = new Random();
		
		EventEmitter(DetectionPoint detectionPoint, int lowerBoundSeconds, int upperBoundSeconds) {
			this.detectionPoint = detectionPoint;
			this.lowerBoundSeconds = lowerBoundSeconds;
			this.upperBoundSeconds = upperBoundSeconds;
		}
		
		@Override
		public void run() {
			while(true) {
				// pick a random user and detection system
				User user = users[random.nextInt(users.length)];
				DetectionSystem detectionSystem = detectionSystems[random.nextInt(detectionSystems.length)];
				
				sleep(randInt(lowerBoundSeconds, upperBoundSeconds));
				System.err.format("Sending event type '%s' from user '%s' and system '%s'%s", 
						detectionPoint.getLabel(), user.getUsername(), detectionSystem.getDetectionSystemId(), System.getProperty("line.separator"));
				try {
					Event event = new Event(user, detectionPoint, detectionSystem);
					System.err.println("sending || " + gson.toJson(event) + " ||");

//					configuration.getServerConnection().setClientApplicationIdentificationHeaderValue(detectionSystem.getDetectionSystemId());
					eventManager.updateApplicationIdentificationHeaderValue(detectionSystem.getDetectionSystemId());
					eventManager.addEvent(event);
				} catch(Exception e) {
					System.err.println("Exception type: " + e.getClass().getCanonicalName());
					e.printStackTrace();
				}
			}
		}
		
		private int randInt(int min, int max) {
		    // nextInt is normally exclusive of the top value,
		    // so add 1 to make it inclusive
		    int randomNum = random.nextInt((max - min) + 1) + min;

		    return randomNum;
		}
		
		private void sleep(int seconds) {
			try {
				Thread.sleep(seconds * 1000);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		
	}
}
