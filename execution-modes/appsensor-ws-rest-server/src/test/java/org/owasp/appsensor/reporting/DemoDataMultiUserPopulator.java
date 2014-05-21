package org.owasp.appsensor.reporting;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

import javax.inject.Inject;
import javax.inject.Named;

import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Interval;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.Threshold;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.server.ServerConfiguration;

/**
 * Provide demo data for websockets test web app.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@Named
public class DemoDataMultiUserPopulator {
	
	@Inject
	private AppSensorServer appSensorServer;
	
	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "myclientapp";
	
	public static void main(String[] args) throws Exception {
		int delay = 50;
		int maxEvents = 80;
		
		new DemoDataMultiUserPopulator().generateData(delay, maxEvents);
	}
	
	public void generateData(int delay, int maxEvents) {
		detectionPoint1.setLabel("IE1");
		detectionSystems1.add(detectionSystem1);
		
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);
		
		int i = 0;
		
		while (i < maxEvents) {
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			
			if(i % 2 == 0) {
				appSensorServer.getEventStore().addEvent(new Event(bob, detectionPoint1, "localhostme"));
			} else {
				int randomNumber = new Random().nextInt() % 99;
				User user = new User("otherUser" + randomNumber);
				appSensorServer.getEventStore().addEvent(new Event(user, detectionPoint1, "localhostme"));
			}
			
			i++;
		}
	}
	
	private static Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes11 = new Interval(11, Interval.MINUTES);
		Interval minutes31 = new Interval(31, Interval.MINUTES);
		
		Threshold events3minutes5 = new Threshold(3, minutes5);
		
		Response log = new Response();
		log.setAction("log");
		
		Response logout = new Response();
		logout.setAction("logout");
		
		Response disableUser = new Response();
		disableUser.setAction("disableUser");
		
		Response disableComponentForSpecificUser31 = new Response();
		disableComponentForSpecificUser31.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser31.setInterval(minutes31);
		
		Response disableComponentForAllUsers11 = new Response();
		disableComponentForAllUsers11.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers11.setInterval(minutes11);
		
		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		point1Responses.add(disableComponentForSpecificUser31);
		point1Responses.add(disableComponentForAllUsers11);
		
		DetectionPoint point1 = new DetectionPoint("IE1", events3minutes5, point1Responses);
		
		configuredDetectionPoints.add(point1);

		return configuredDetectionPoints;
	}
	
}
