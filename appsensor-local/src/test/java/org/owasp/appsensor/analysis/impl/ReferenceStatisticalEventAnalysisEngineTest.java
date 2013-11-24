package org.owasp.appsensor.analysis.impl;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;

import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.ClientObjectFactory;
import org.owasp.appsensor.DetectionPoint;
import org.owasp.appsensor.ServerObjectFactory;
import org.owasp.appsensor.StatisticalEvent;
import org.owasp.appsensor.User;

public class ReferenceStatisticalEventAnalysisEngineTest {

	private static User bob = new User("bob", "1.2.3.4");
	
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
//		StatisticalEvent tmp = new StatisticalEvent(bob, detectionPoint1, "localhostme");
//		Gson gson = new GsonBuilder().setPrettyPrinting().create();
//		System.err.println(gson.toJson(tmp));
		
		assertEquals(0, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(1, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(2, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(0, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(3, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(4, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(5, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(1, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(6, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(2, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
		
		ClientObjectFactory.getEventManager().addEvent(new StatisticalEvent(bob, detectionPoint1, "localhostme"));
		
		assertEquals(7, ServerObjectFactory.getEventStore().findEvents(bob, detectionPoint1, detectionSystems1).size());
		assertEquals(2, ServerObjectFactory.getAttackStore().findAttacks(bob, detectionPoint1, detectionSystems1).size());
	}
	
}
