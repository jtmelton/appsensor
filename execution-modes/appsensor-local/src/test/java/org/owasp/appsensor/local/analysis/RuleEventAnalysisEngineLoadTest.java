package org.owasp.appsensor.local.analysis;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import javax.inject.Inject;

import org.hibernate.Criteria;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.analysis.AggregateEventAnalysisEngine;
import org.owasp.appsensor.analysis.Rule;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.Attack;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.storage.memory.InMemoryAttackStore;
import org.owasp.appsensor.storage.memory.InMemoryEventStore;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;


/**
 * Test the load capacity of advanced {@link Rule} {@link Event} analysis engine.
 * The goal is to blast the engine with a super high rate of events and see if it
 * is able to process it accurately and timely.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class RuleEventAnalysisEngineLoadTest {

	private static User bob = new User("bob");
	private static DetectionPoint detectionPoint1 = new DetectionPoint();
	private static DetectionPoint detectionPoint2 = new DetectionPoint();
	private static DetectionPoint detectionPoint3 = new DetectionPoint();
	private static DetectionPoint detectionPoint4 = new DetectionPoint();
	private static DetectionPoint detectionPoint5 = new DetectionPoint();
	private static DetectionPoint detectionPoint6 = new DetectionPoint();
	private static DetectionPoint detectionPoint7 = new DetectionPoint();
	private static DetectionPoint detectionPoint8 = new DetectionPoint();
	private static DetectionPoint detectionPoint9 = new DetectionPoint();
	private static DetectionPoint detectionPoint10 = new DetectionPoint();
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	private static DetectionSystem detectionSystem1 = new DetectionSystem("localhostme");

	private static SearchCriteria criteriaDP;
	private static SearchCriteria criteriaRule;

	private static AggregateEventAnalysisEngine myEngine = null;

	//private static ArrayList<Rule> rules = null;
	private static Rule rule1 = null;
	private static Rule rule2 = null;

	protected int sleepAmount = 10;

	@Inject
	AppSensorServer appSensorServer;

	@Inject
	AppSensorClient appSensorClient;

	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint2.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint3.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint4.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint5.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint6.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint7.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint8.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint9.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint10.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE1");
		detectionPoint2.setLabel("IE2");
		detectionPoint3.setLabel("IE3");
		detectionPoint4.setLabel("IE4");
		detectionPoint5.setLabel("IE5");
		detectionPoint6.setLabel("IE6");
		detectionPoint7.setLabel("IE7");
		detectionPoint8.setLabel("IE8");
		detectionPoint9.setLabel("IE9");
		detectionPoint10.setLabel("IE10");

		detectionSystems1.add(detectionSystem1.getDetectionSystemId());

		criteriaDP = new SearchCriteria().
				setUser(bob).
				setDetectionSystemIds(detectionSystems1);

		criteriaRule = new SearchCriteria().
				setUser(new User("bobR"));

		rule1 = generateRule1();
		rule2 = generateRule2();
	}

	public void initialSetup() {
		//instantiate server
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);

		Collection<EventAnalysisEngine> engines = appSensorServer.getEventAnalysisEngines();

		for (EventAnalysisEngine engine : engines) {
			if (engine instanceof AggregateEventAnalysisEngine){
				myEngine = (AggregateEventAnalysisEngine)engine;
			}
		}
	}

	@Before
	public void initializeTest() {
		if (myEngine == null) {
			initialSetup();
		}

		myEngine.clearRules();

		((InMemoryAttackStore) appSensorServer.getAttackStore()).clearAll();
		((InMemoryEventStore) appSensorServer.getEventStore()).clearAll();
	}

	@Test
	public void test1() throws Exception {
		int COUNT = 0;

		//Add rules
		for (int i=0; i<10; i++) {
			myEngine.addRule(rule1);
		}

		for (int i=0; i<COUNT; i++) {
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint1, new DetectionSystem("localhostme")));
			//Thread.sleep(1);
		}

		assertEquals(COUNT, appSensorServer.getEventStore().findEvents(criteriaDP).size());
		assertEquals(COUNT/10, appSensorServer.getAttackStore().findAttacks(criteriaRule).size());
	}


	@Test
	public void test2() throws Exception {
		int COUNT = 0;

		ArrayList<DetectionPoint>detectionPoints = new ArrayList<DetectionPoint>();
		detectionPoints.add(detectionPoint1);
		detectionPoints.add(detectionPoint2);
		detectionPoints.add(detectionPoint3);
		detectionPoints.add(detectionPoint4);
		detectionPoints.add(detectionPoint5);
		detectionPoints.add(detectionPoint6);
		detectionPoints.add(detectionPoint7);
		detectionPoints.add(detectionPoint8);
		detectionPoints.add(detectionPoint9);
		detectionPoints.add(detectionPoint10);

		//Add rules
		for (int i=0; i<10; i++) {
			myEngine.addRule(rule2);
		}

		//write test results out
		File file = new File("/home/david/loadTest.txt");
		PrintWriter writer = new PrintWriter(file, "UTF-8");

		int[] delays = {0, 5, 10, 25, 50, 75, 100, 150, 200, 250, 500, 750, 1000, 2000};
		for (int delay : delays) {
			//clear stores
			((InMemoryAttackStore) appSensorServer.getAttackStore()).clearAll();
			((InMemoryEventStore) appSensorServer.getEventStore()).clearAll();

			long startTime = System.nanoTime();

			//generate random events
			for (int i=0; i<COUNT; i++) {
				int rand = (int)(Math.random()*10);
				appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoints.get(rand), new DetectionSystem("localhostme")));
				Thread.sleep(delay);
			}

			long elapsedTime = System.nanoTime() - startTime;
			writer.format("delay: %d, time: %d\n", delay, elapsedTime);

		}

		writer.close();

		assertEquals(COUNT*delays.length, appSensorServer.getEventStore().findEvents(criteriaDP).size());
	}

	@Test
	public void test3() throws Exception {

		ArrayList<DetectionPoint>detectionPoints = new ArrayList<DetectionPoint>();
		detectionPoints.add(detectionPoint1);
		detectionPoints.add(detectionPoint2);
		detectionPoints.add(detectionPoint3);
		detectionPoints.add(detectionPoint4);
		detectionPoints.add(detectionPoint5);
		detectionPoints.add(detectionPoint6);
		detectionPoints.add(detectionPoint7);
		detectionPoints.add(detectionPoint8);
		detectionPoints.add(detectionPoint9);
		detectionPoints.add(detectionPoint10);

		//Add rules
		for (int i=0; i<10; i++) {
			myEngine.addRule(rule2);
		}

		//write test results out
		File file = new File("/home/david/loadCountTest.txt");
		PrintWriter writer = new PrintWriter(file, "UTF-8");

		int[] counts = {0, 5, 10, 25, 50, 75, 100, 150, 200, 250, 500, 750, 1000};
		for (int count : counts) {
			//clear stores
			((InMemoryAttackStore) appSensorServer.getAttackStore()).clearAll();
			((InMemoryEventStore) appSensorServer.getEventStore()).clearAll();

			long startTime = System.nanoTime();

			//generate random events
			for (int i=0; i<count; i++) {
				int rand = (int)(Math.random()*10);
				appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoints.get(rand), new DetectionSystem("localhostme")));
			}

			long elapsedTime = System.nanoTime() - startTime;
			writer.format("count: %d, time: %d\n", count, elapsedTime);

		}

		writer.close();
	}

	private static Rule generateRule1() {
		/*
		Interval minutes1 = new Interval(1, Interval.MINUTES);
		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(10, minutes1));

		DetectionPointVariable detectionPointVariable1 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point1);

		//rule 1: DP1
		ArrayList<DetectionPointVariable> detectionPointVariables1 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables1.add(detectionPointVariable1);

		org.owasp.appsensor.analysis.Expression expression1 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions1 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions1.add(expression1);

		return new Rule("Rule 1", minutes1, expressions1);
		*/
		return null;
	}

	private static Rule generateRule2() {
		/*
		Interval minutes1 = new Interval(1, Interval.MINUTES);
		Interval minutes10 = new Interval(10, Interval.MINUTES);

		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(10, minutes1));
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", new Threshold(10, minutes1));
		DetectionPoint point3 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", new Threshold(10, minutes1));
		DetectionPoint point4 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE4", new Threshold(10, minutes1));
		DetectionPoint point5 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE5", new Threshold(10, minutes1));
		DetectionPoint point6 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE6", new Threshold(10, minutes1));
		DetectionPoint point7 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE7", new Threshold(10, minutes1));
		DetectionPoint point8 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE8", new Threshold(10, minutes1));
		DetectionPoint point9 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE9", new Threshold(10, minutes1));
		DetectionPoint point10 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE10", new Threshold(10, minutes1));

		DetectionPointVariable detectionPointVariable1 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point1);
		DetectionPointVariable detectionPointVariable2 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point2);
		DetectionPointVariable detectionPointVariable3 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point3);
		DetectionPointVariable detectionPointVariable4 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point4);
		DetectionPointVariable detectionPointVariable5 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point5);
		DetectionPointVariable detectionPointVariable6 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point6);
		DetectionPointVariable detectionPointVariable7 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point7);
		DetectionPointVariable detectionPointVariable8 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point8);
		DetectionPointVariable detectionPointVariable9 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point9);
		DetectionPointVariable detectionPointVariable10 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point10);

		//rule 2: 1 or 2 or 3 or 4 or 5 or 6 or 7 or 8 or 9 or 10 (x10)
		ArrayList<DetectionPointVariable> detectionPointVariables1 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables1.add(detectionPointVariable1);
		detectionPointVariables1.add(detectionPointVariable2);
		detectionPointVariables1.add(detectionPointVariable3);
		detectionPointVariables1.add(detectionPointVariable4);
		detectionPointVariables1.add(detectionPointVariable5);
		detectionPointVariables1.add(detectionPointVariable6);
		detectionPointVariables1.add(detectionPointVariable7);
		detectionPointVariables1.add(detectionPointVariable8);
		detectionPointVariables1.add(detectionPointVariable9);
		detectionPointVariables1.add(detectionPointVariable10);

		org.owasp.appsensor.analysis.Expression expression1 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression2 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression3 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression4 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression5 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression6 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression7 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression8 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression9 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);
		org.owasp.appsensor.analysis.Expression expression10 = new org.owasp.appsensor.analysis.Expression(minutes1, detectionPointVariables1);

		ArrayList<org.owasp.appsensor.analysis.Expression> expressions1 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions1.add(expression1);
		expressions1.add(expression2);
		expressions1.add(expression3);
		expressions1.add(expression4);
		expressions1.add(expression5);
		expressions1.add(expression6);
		expressions1.add(expression7);
		expressions1.add(expression8);
		expressions1.add(expression9);
		expressions1.add(expression10);

		return new Rule("Rule 2", minutes10, expressions1);
		*/
		return null;
	}

	private static Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		Interval minutes1 = new Interval(1, Interval.MINUTES);

		Threshold events10minutes1 = new Threshold(10, minutes1);

		Response log = new Response();
		log.setAction("log");

		Response logout = new Response();
		logout.setAction("logout");

		Response disableUser = new Response();
		disableUser.setAction("disableUser");

		Response disableComponentForSpecificUser10 = new Response();
		disableComponentForSpecificUser10.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser10.setInterval(minutes1);

		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		point1Responses.add(disableComponentForSpecificUser10);

		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events10minutes1, point1Responses);
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", events10minutes1, point1Responses);
		DetectionPoint point3 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", events10minutes1, point1Responses);
		DetectionPoint point4 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE4", events10minutes1, point1Responses);
		DetectionPoint point5 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE5", events10minutes1, point1Responses);
		DetectionPoint point6 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE6", events10minutes1, point1Responses);
		DetectionPoint point7 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE7", events10minutes1, point1Responses);
		DetectionPoint point8 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE8", events10minutes1, point1Responses);
		DetectionPoint point9 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE9", events10minutes1, point1Responses);
		DetectionPoint point10 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE10", events10minutes1, point1Responses);

		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);
		configuredDetectionPoints.add(point3);
		configuredDetectionPoints.add(point4);
		configuredDetectionPoints.add(point5);
		configuredDetectionPoints.add(point6);
		configuredDetectionPoints.add(point7);
		configuredDetectionPoints.add(point8);
		configuredDetectionPoints.add(point9);
		configuredDetectionPoints.add(point10);


		return configuredDetectionPoints;
	}
}