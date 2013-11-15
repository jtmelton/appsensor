package org.owasp.appsensor.analysis.impl;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.ClientObjectFactory;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.Event;
import org.owasp.appsensor.Interval;
import org.owasp.appsensor.Response;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.Threshold;
import org.owasp.appsensor.User;

public class ReferenceEventAnalysisEngineTest {

	private static User bob = new User("bob", "1.2.3.4");
	
	private static Interval fiveMinutes = new Interval(5, Interval.MINUTES);
	private static Interval thirtySeconds = new Interval(30, Interval.SECONDS);
	
	private static Threshold threeInFiveMinutes = new Threshold(3, fiveMinutes);
	
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	
	private static Collection<Response> responses1 = new ArrayList<Response>();
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static String detectionSystem1 = "localhostme";
	
	@BeforeClass
	public static void doSetup() {
		responses1.add(new Response(bob, "log", detectionPoint1, detectionSystem1));
		responses1.add(new Response(bob, "logout", detectionPoint1, detectionSystem1));
		responses1.add(new Response(bob, "disableUser", detectionPoint1, detectionSystem1));
		responses1.add(new Response(bob, "disableComponentForAllUsers", detectionPoint1, detectionSystem1, thirtySeconds));
		
		detectionPoint1.setId("IE1");
		detectionPoint1.setThreshold(threeInFiveMinutes);
		detectionPoint1.setResponses(responses1);
		
		detectionSystems1.add(detectionSystem1);
	}
	
	@Test
	public void testAttackCreation() throws Exception {
		assertEquals(0, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(1, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(2, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(3, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(4, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(5, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(6, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(2, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new Event(bob, detectionPoint1, "localhostme"));
		
		assertEquals(7, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(2, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
	}
	
}
