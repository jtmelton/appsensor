package org.owasp.appsensor.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.AppSensorClient;
import org.owasp.appsensor.AppSensorServer;
import org.owasp.appsensor.Attack;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Interval;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.Threshold;
import org.owasp.appsensor.User;
import org.owasp.appsensor.configuration.server.ServerConfiguration;
import org.owasp.appsensor.criteria.SearchCriteria;

/**
 * Test basic {@link Event} analysis engine. Add a number of {@link Event}s matching 
 * the known set of criteria and ensure the {@link Attack}s are triggered at 
 * the appropriate points.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class ReferenceStatisticalEventAnalysisEngineTest {

	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "localhostme";
	
	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setId("IE1");
		
		detectionSystems1.add(detectionSystem1);
	}
	
	@Test
	public void testAttackCreation() throws Exception {
		AppSensorServer.bootstrap();
		AppSensorClient.bootstrap();
		
		ServerConfiguration updatedConfiguration = AppSensorServer.getInstance().getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		AppSensorServer.getInstance().setConfiguration(updatedConfiguration);

		SearchCriteria criteria = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1);
		
		assertEquals(0, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(0, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(1, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(0, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(2, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(0, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(3, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(1, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(4, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(1, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(5, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(1, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(6, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(2, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
		
		AppSensorClient.getInstance().getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(7, AppSensorServer.getInstance().getEventStore().findEvents(criteria).size());
		assertEquals(2, AppSensorServer.getInstance().getAttackStore().findAttacks(criteria).size());
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
		
		DetectionPoint point1 = new DetectionPoint("IE1", events3minutes5, point1Responses);
		
		Collection<Response> point2Responses = new ArrayList<Response>();
		point2Responses.add(log);
		point2Responses.add(logout);
		point2Responses.add(disableUser);
		point2Responses.add(disableComponentForSpecificUser32);
		point2Responses.add(disableComponentForAllUsers12);
		
		DetectionPoint point2 = new DetectionPoint("IE2", events12minutes5, point2Responses);
		
		Collection<Response> point3Responses = new ArrayList<Response>();
		point3Responses.add(log);
		point3Responses.add(logout);
		point3Responses.add(disableUser);
		point3Responses.add(disableComponentForSpecificUser33);
		point3Responses.add(disableComponentForAllUsers13);
		
		DetectionPoint point3 = new DetectionPoint("IE3", events13minutes6, point3Responses);
		
		Collection<Response> point4Responses = new ArrayList<Response>();
		point4Responses.add(log);
		point4Responses.add(logout);
		point4Responses.add(disableUser);
		point4Responses.add(disableComponentForSpecificUser34);
		point4Responses.add(disableComponentForAllUsers14);
		
		DetectionPoint point4 = new DetectionPoint("IE4", events14minutes7, point4Responses);
		
		Collection<Response> point5Responses = new ArrayList<Response>();
		point5Responses.add(log);
		point5Responses.add(logout);
		point5Responses.add(disableUser);
		point5Responses.add(disableComponentForSpecificUser35);
		point5Responses.add(disableComponentForAllUsers15);
		
		DetectionPoint point5 = new DetectionPoint("IE5", events15minutes8, point5Responses);
		
		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);
		configuredDetectionPoints.add(point3);
		configuredDetectionPoints.add(point4);
		configuredDetectionPoints.add(point5);

		return configuredDetectionPoints;
	}
	
}
