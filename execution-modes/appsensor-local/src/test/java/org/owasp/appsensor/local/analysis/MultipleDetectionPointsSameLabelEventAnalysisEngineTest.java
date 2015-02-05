package org.owasp.appsensor.local.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test basic {@link Event} analysis engine. Add a number of {@link Event}s matching 
 * the known set of criteria and ensure the {@link Attack}s are triggered at 
 * the appropriate points.
 * 
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class MultipleDetectionPointsSameLabelEventAnalysisEngineTest {

	private static User bob = new User("bob");
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "localhostme";
	
	@Inject
	AppSensorServer appSensorServer;
	
	@Inject
	AppSensorClient appSensorClient;
	
	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setCategory(DetectionPoint.Category.REQUEST);
		detectionPoint1.setLabel("RE7");
		
		detectionSystems1.add(detectionSystem1);
	}
	
	@Test
	public void testAttackCreationMultipleDetectionPointsOneLabel() throws Exception {

		SearchCriteria criteria = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1);
		
		assertEquals(2, appSensorServer.getConfiguration().findDetectionPoints(detectionPoint1).size());
		
		assertEquals(0, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(1, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(0, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(2, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(3, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(4, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(5, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(3, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(6, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(4, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(7, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(4, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(8, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(5, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(9, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(5, appSensorServer.getAttackStore().findAttacks(criteria).size());
		
		appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		Thread.sleep(500);
		
		assertEquals(10, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(7, appSensorServer.getAttackStore().findAttacks(criteria).size());
	}
	
}
