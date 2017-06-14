package org.owasp.appsensor.local.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import javax.inject.Inject;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.analysis.AggregateEventAnalysisEngine;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.User;
import org.owasp.appsensor.core.analysis.EventAnalysisEngine;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.MonitorPoint;
import org.owasp.appsensor.core.rule.Rule;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Basic test for the {@link AggregateEventAnalysisEngine}. Built to be extended by other components
 * to test integration with the rules engine.
 *
 * Tests should finish with the last event triggering an attack, so that each test can start
 * assuming that only the events created in each test will count towards the attack threshold.
 * todo: fix this by clearing events or adding time before each test
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class SimpleAggregateEventAnalysisEngineTest {

	protected static User bob = new User("bob");

	protected static ArrayList<DetectionPoint> detectionPoints = null;

	protected static Collection<String> detectionSystems1 = new ArrayList<String>();

	protected static DetectionSystem detectionSystem1 = new DetectionSystem("localhostme");

	protected static HashMap<String, SearchCriteria> criteria = new HashMap<String, SearchCriteria>();

	protected static AggregateEventAnalysisEngine rulesEngine = null;

	protected static ArrayList<Rule> rules = null;

	protected static DateTime time;

	protected static int SLEEP_AMOUNT = 10;

	@Inject
	AppSensorServer appSensorServer;

	@Inject
	AppSensorClient appSensorClient;

	@BeforeClass
	public static void doSetup() {
		// instantiate member variables

		detectionSystems1.add(detectionSystem1.getDetectionSystemId());

		detectionPoints = generateDetectionPoints();

		rules = generateRules();

		criteria.put("all", new SearchCriteria().setDetectionSystemIds(detectionSystems1));

		criteria.put("dp1", new SearchCriteria().
				setDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1")).
				setDetectionSystemIds(detectionSystems1));


		criteria.put("rule1", new SearchCriteria().
				setRule(rules.get(0)).
				setDetectionSystemIds(detectionSystems1));

		time = DateTime.now().minusMinutes(2).toDateTime(DateTimeZone.UTC);
	}

	@Before
	public void initializeTest() {
		rulesEngine = getRulesEngine();

		// clear any existing rules & detection points
		ArrayList<Rule> emptyRules = new ArrayList<Rule>();
		appSensorServer.getConfiguration().setRules(emptyRules);

		ArrayList<DetectionPoint> emptyDps = new ArrayList<DetectionPoint>();
		appSensorServer.getConfiguration().setDetectionPoints(emptyDps);
	}

	@Test
	public void test1_DP1() throws Exception {
		// add rules/detection points
		ArrayList<Rule> rulesToAdd = new ArrayList<Rule>();
		rulesToAdd.add(rules.get(0));
		appSensorServer.getConfiguration().setRules(rulesToAdd);

		// add detection point
		ArrayList<DetectionPoint> dpsToAdd = new ArrayList<DetectionPoint>();
		dpsToAdd.add(detectionPoints.get(0));
		appSensorServer.getConfiguration().setDetectionPoints(dpsToAdd);

		DetectionPoint detectionPoint1 = detectionPoints.get(0);

		// get events and attacks
		int numEvents = appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size();
		int numDPAttacks = appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size();
		int numRuleAttacks = appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size();

		// useless sanity check
		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());


		// 3 events and triggered attack
		addEvents(bob, detectionPoint1, 3);
		numEvents += 3; numDPAttacks++; numRuleAttacks++;

		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

		// 1 event and no new attack
		addEvent(bob, detectionPoint1);
		numEvents += 1;

		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

		// 2 events and 2 total attack
		addEvents(bob, detectionPoint1, 2);
		numEvents += 2; numDPAttacks++; numRuleAttacks++;

		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());
	}

	protected void addEvent(User user, DetectionPoint detectionPoint) {
		appSensorClient.getEventManager().addEvent(new Event(user, detectionPoint, time.toString(), detectionSystem1));
		time = time.plusMillis(SLEEP_AMOUNT);

	}

	protected void addEvents(User user, DetectionPoint detectionPoint, int count) {
		for (int i=0; i<count; i++) {
			appSensorClient.getEventManager().addEvent(new Event(user, detectionPoint, time.toString(), detectionSystem1));
			time = time.plusMillis(SLEEP_AMOUNT);
		}
	}

	private static ArrayList<Rule> generateRules() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		// intervals
		Interval minutes5 = new Interval(5, Interval.MINUTES);

		// detection points
		MonitorPoint point1 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(3, minutes5)));
		point1.setGuid("00000000-0000-0000-0000-000000000000");

		// clauses
		ArrayList<DetectionPoint> points1 = new ArrayList<DetectionPoint>();
		points1.add(point1);

		Clause clause1 = new Clause(points1);

		// responses
		ArrayList<Response> responses = generateResponses();

		// rule 1: DP1
		ArrayList<Clause> clauses1 = new ArrayList<Clause>();
		clauses1.add(clause1);

		org.owasp.appsensor.core.rule.Expression expression1 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1.add(expression1);

		configuredRules.add(new Rule("00000000-0000-0000-0000-000000000011", minutes5, expressions1, responses, "Rule 1"));

		return configuredRules;
	}

	private static ArrayList<DetectionPoint> generateDetectionPoints() {
		ArrayList<DetectionPoint> detectionPoints = new ArrayList<DetectionPoint>();

		// dp1: 3 events in 5 minutes
		DetectionPoint detectionPoint1 = new DetectionPoint();

		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE1");
		detectionPoint1.setThreshold(new Threshold(3, new Interval(5, Interval.MINUTES)));
		detectionPoint1.setResponses(generateResponses());

		detectionPoints.add(detectionPoint1);

		return detectionPoints;
	}

	private static ArrayList<Response> generateResponses() {
		Interval minutes5 = new Interval(5, Interval.MINUTES);

		Response log = new Response();
		log.setAction("log");

		Response logout = new Response();
		logout.setAction("logout");

		Response disableUser = new Response();
		disableUser.setAction("disableUser");

		Response disableComponentForSpecificUser5 = new Response();
		disableComponentForSpecificUser5.setAction("disableComponentForSpecificUser");
		disableComponentForSpecificUser5.setInterval(minutes5);

		Response disableComponentForAllUsers5 = new Response();
		disableComponentForAllUsers5.setAction("disableComponentForAllUsers");
		disableComponentForAllUsers5.setInterval(minutes5);

		ArrayList<Response> responses = new ArrayList<Response>();
		responses.add(log);
		responses.add(logout);
		responses.add(disableUser);
		responses.add(disableComponentForSpecificUser5);
		responses.add(disableComponentForAllUsers5);

		return responses;
	}

	public AggregateEventAnalysisEngine getRulesEngine() {
		Collection<EventAnalysisEngine> engines = appSensorServer.getEventAnalysisEngines();

		for (EventAnalysisEngine engine : engines) {
			if (engine instanceof AggregateEventAnalysisEngine){
				return (AggregateEventAnalysisEngine)engine;
			}
		}

		return null;
	}
}