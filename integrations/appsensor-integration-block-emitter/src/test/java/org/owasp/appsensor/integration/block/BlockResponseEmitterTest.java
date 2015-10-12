package org.owasp.appsensor.integration.block;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.IPAddress;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Resource;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.integration.block.BlockResponseEmitter;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test influxdb notification by extending the ReferenceStatisticalEventAnalysisEngineTest. 
 * All of the same tests execute, but we're just verifying the influx work
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:applicationContext.xml"})
public class BlockResponseEmitterTest {
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "my-sample-client";
    
	@Inject 
	Environment environment;
	
	@Inject IPAddress ipAddress;
	
    @Inject
	AppSensorServer appSensorServer;
	
	@Inject
	AppSensorClient appSensorClient;

	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE15");
		
		detectionSystems1.add(detectionSystem1);
	}
	
	@Test
	public void testAttackCreation() throws Exception {
		if(! isInitializedProperly()) {
			System.err.println("Test not running because environment variables are not setup properly.");
		} else {
			
			ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
			updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
			appSensorServer.setConfiguration(updatedConfiguration);
	
			User bob = new User("bob", ipAddress.fromString("127.0.0.1"));
			
			Resource resource = new Resource();
			resource.setLocation("/some-url");
			
			SearchCriteria criteria = new SearchCriteria().
					setUser(bob).
					setDetectionPoint(detectionPoint1).
					setDetectionSystemIds(detectionSystems1);
			
			assertEquals(0, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(1, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(2, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(3, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(4, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(5, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(6, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(7, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(8, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(9, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(3, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(10, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(3, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(11, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(3, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(12, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(4, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(13, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(4, appSensorServer.getAttackStore().findAttacks(criteria).size());
			
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("my-sample-client")).setResource(resource));
			assertEquals(14, appSensorServer.getEventStore().findEvents(criteria).size());
			assertEquals(4, appSensorServer.getAttackStore().findAttacks(criteria).size());
		}
	}
	
	private boolean isInitializedProperly() {
		return StringUtils.isNotBlank(environment.getProperty(BlockResponseEmitter.BLOCK_STORE_URL));

	}
	
	private Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		Interval minutes1 = new Interval(1, Interval.MINUTES);
		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval seconds20 = new Interval(20, Interval.SECONDS);
		Interval seconds45 = new Interval(45, Interval.SECONDS);
		
		Threshold events3minutes5 = new Threshold(3, minutes5);
		Threshold events3minutes1 = new Threshold(3, minutes1);
		
		Response log = new Response();
		log.setAction("log");
		
		Response logout = new Response();
		logout.setAction("logout");
		
		Response disableUser = new Response();
		disableUser.setAction("disableUser");
		
		Response disableComponentForSpecificUser = new Response();
		disableComponentForSpecificUser.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser.setInterval(seconds20);
		
		Response disableComponentForAllUsers = new Response();
		disableComponentForAllUsers.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers.setInterval(seconds45);
		
		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		
		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events3minutes5, point1Responses);
		
		Collection<Response> point2Responses = new ArrayList<Response>();
		point2Responses.add(log);
		point2Responses.add(disableComponentForSpecificUser);
		point2Responses.add(disableComponentForAllUsers);
		
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE15", events3minutes1, point2Responses);
		
		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);

		return configuredDetectionPoints;
	}
	
}
