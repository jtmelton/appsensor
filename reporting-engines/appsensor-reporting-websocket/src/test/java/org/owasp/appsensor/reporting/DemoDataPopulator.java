package org.owasp.appsensor.reporting;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import javax.inject.Inject;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.IPAddress;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Provide demo data for websockets test web app.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:applicationContext.xml"})
public class DemoDataPopulator {
	
	@Inject
	private AppSensorClient appSensorClient;
	
	@Inject
	private AppSensorServer appSensorServer;
	
	@Inject
	private IPAddress locator; 
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Random random = new Random(); 
	
	public static void main(String[] args) throws Exception {
		new DemoDataPopulator().populateData();
	}
	
	@Test
	public void populateData() throws Exception {
		User user1 = new User("user1 (russia)", locator.fromString("5.45.80.10"));
		User user2 = new User("user2 (canada)", locator.fromString("23.29.201.141"));
		User user3 = new User("user3 (australia)", locator.fromString("27.54.137.119"));
		User user4 = new User("user4 (south africa)", locator.fromString("41.50.10.35"));

		DetectionSystem detectionSystem1 = new DetectionSystem("attacked server1 (Mexico)", locator.fromString("148.208.15.39"));
		DetectionSystem detectionSystem2 = new DetectionSystem("attacked server2 (Italy)", locator.fromString("5.172.75.122"));
		
		List<User> users = Arrays.asList(user1, user2, user3, user4);
		List<DetectionSystem> detectionSystems = Arrays.asList(detectionSystem1, detectionSystem2);
		
		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE1");
		
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);
		
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
		appSensorClient.getEventManager().addEvent(new Event(users.get(random.nextInt(4)), detectionPoint1, detectionSystems.get(random.nextInt(2))));
		Thread.sleep(getDelay());
	}

	// between 500ms and 2,500ms
	private int getDelay() {
		return random.nextInt(2000) + 500;
	}
	
	private Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes6 = new Interval(6, Interval.MINUTES);
		Interval minutes7 = new Interval(7, Interval.MINUTES);
		Interval minutes8 = new Interval(8, Interval.MINUTES);
		Interval minutes11 = new Interval(11, Interval.MINUTES);
		Interval minutes12 = new Interval(12, Interval.MINUTES);
		Interval minutes13 = new Interval(13, Interval.MINUTES);
		Interval minutes14 = new Interval(14, Interval.MINUTES);
		Interval minutes15 = new Interval(15, Interval.MINUTES);
		Interval minutes31 = new Interval(31, Interval.MINUTES);
		Interval minutes32 = new Interval(32, Interval.MINUTES);
		Interval minutes33 = new Interval(33, Interval.MINUTES);
		Interval minutes34 = new Interval(34, Interval.MINUTES);
		Interval minutes35 = new Interval(35, Interval.MINUTES);
		
		Threshold events3minutes5 = new Threshold(3, minutes5);
		Threshold events12minutes5 = new Threshold(12, minutes5);
		Threshold events13minutes6 = new Threshold(13, minutes6);
		Threshold events14minutes7 = new Threshold(14, minutes7);
		Threshold events15minutes8 = new Threshold(15, minutes8);
		
		Response log = new Response();
		log.setAction("log");
		
		Response logout = new Response();
		logout.setAction("logout");
		
		Response disableUser = new Response();
		disableUser.setAction("disableUser");
		
		Response disableComponentForSpecificUser31 = new Response();
		disableComponentForSpecificUser31.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser31.setInterval(minutes31);
		
		Response disableComponentForSpecificUser32 = new Response();
		disableComponentForSpecificUser32.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser32.setInterval(minutes32);
		
		Response disableComponentForSpecificUser33 = new Response();
		disableComponentForSpecificUser33.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser33.setInterval(minutes33);
		
		Response disableComponentForSpecificUser34 = new Response();
		disableComponentForSpecificUser34.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser34.setInterval(minutes34);
		
		Response disableComponentForSpecificUser35 = new Response();
		disableComponentForSpecificUser35.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser35.setInterval(minutes35);
		
		Response disableComponentForAllUsers11 = new Response();
		disableComponentForAllUsers11.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers11.setInterval(minutes11);
		
		Response disableComponentForAllUsers12 = new Response();
		disableComponentForAllUsers12.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers12.setInterval(minutes12);
		
		Response disableComponentForAllUsers13 = new Response();
		disableComponentForAllUsers13.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers13.setInterval(minutes13);
		
		Response disableComponentForAllUsers14 = new Response();
		disableComponentForAllUsers14.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers14.setInterval(minutes14);
		
		Response disableComponentForAllUsers15 = new Response();
		disableComponentForAllUsers15.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers15.setInterval(minutes15);
		
		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		point1Responses.add(disableComponentForSpecificUser31);
		point1Responses.add(disableComponentForAllUsers11);
		
		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events3minutes5, point1Responses);
		
		Collection<Response> point2Responses = new ArrayList<Response>();
		point2Responses.add(log);
		point2Responses.add(logout);
		point2Responses.add(disableUser);
		point2Responses.add(disableComponentForSpecificUser32);
		point2Responses.add(disableComponentForAllUsers12);
		
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", events12minutes5, point2Responses);
		
		Collection<Response> point3Responses = new ArrayList<Response>();
		point3Responses.add(log);
		point3Responses.add(logout);
		point3Responses.add(disableUser);
		point3Responses.add(disableComponentForSpecificUser33);
		point3Responses.add(disableComponentForAllUsers13);
		
		DetectionPoint point3 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", events13minutes6, point3Responses);
		
		Collection<Response> point4Responses = new ArrayList<Response>();
		point4Responses.add(log);
		point4Responses.add(logout);
		point4Responses.add(disableUser);
		point4Responses.add(disableComponentForSpecificUser34);
		point4Responses.add(disableComponentForAllUsers14);
		
		DetectionPoint point4 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE4", events14minutes7, point4Responses);
		
		Collection<Response> point5Responses = new ArrayList<Response>();
		point5Responses.add(log);
		point5Responses.add(logout);
		point5Responses.add(disableUser);
		point5Responses.add(disableComponentForSpecificUser35);
		point5Responses.add(disableComponentForAllUsers15);
		
		DetectionPoint point5 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE5", events15minutes8, point5Responses);
		
		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);
		configuredDetectionPoints.add(point3);
		configuredDetectionPoints.add(point4);
		configuredDetectionPoints.add(point5);

		return configuredDetectionPoints;
	}
	
}
