package org.owasp.appsensor.local.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.rule.RulesDetectionPoint;
import org.owasp.appsensor.storage.memory.InMemoryAttackStore;
import org.owasp.appsensor.storage.memory.InMemoryEventStore;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Unit tests for the {@link AggregateEventAnalysisEngine}.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class AggregateEventAnalysisEngineIntegrationTest {

	private static User bob = new User("bob");

	private static DetectionPoint detectionPoint1 = new DetectionPoint();

	private static DetectionPoint detectionPoint2 = new DetectionPoint();

	private static DetectionPoint detectionPoint3 = new DetectionPoint();

	private static DetectionPoint detectionPoint5 = new DetectionPoint();

	private static Collection<String> detectionSystems1 = new ArrayList<String>();

	private static DetectionSystem detectionSystem1 = new DetectionSystem("localhostme");

	private static HashMap<String, SearchCriteria> criteria = new HashMap<String, SearchCriteria>();

	private static AggregateEventAnalysisEngine myEngine = null;

	private static ArrayList<Rule> rules = null;

	protected int sleepAmount = 10;

	@Inject
	AppSensorServer appSensorServer;

	@Inject
	AppSensorClient appSensorClient;

	@BeforeClass
	public static void doSetup() {
		detectionPoint1.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint1.setLabel("IE1");
		detectionPoint1.setThreshold(new Threshold(3, new Interval(5, Interval.MINUTES)));

		detectionPoint2.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint2.setLabel("IE2");
		detectionPoint2.setThreshold(new Threshold(12, new Interval(5, Interval.MINUTES)));

		detectionPoint3.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint3.setLabel("IE3");
		detectionPoint3.setThreshold(new Threshold(13, new Interval(6, Interval.MINUTES)));


		detectionPoint5.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint5.setLabel("IE5");

		detectionSystems1.add(detectionSystem1.getDetectionSystemId());

		criteria.put("all", new SearchCriteria().setDetectionSystemIds(detectionSystems1));

		criteria.put("dp1", new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("dp2", new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint2).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("dp3", new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint3).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("dp5", new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint5).
				setDetectionSystemIds(detectionSystems1));

		rules = generateRules();

		criteria.put("rule1", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(0)).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("rule2", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(1)).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("rule3", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(2)).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("rule4", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(3)).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("rule5", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(4)).
				setDetectionSystemIds(detectionSystems1));

		criteria.put("rule6", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(5)).
				setDetectionSystemIds(detectionSystems1));
	}

	@Before
	public void initializeTest() {
		if (myEngine == null) {
			initialSetup();
		}
		clearStores();

		// clear rules
		setRule(appSensorServer, null);
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

	@Test
	public void test1_DP1() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(0));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule1");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

		generateEvents(sleepAmount, detectionPoint1, 1, "rule1");
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());
	}

	@Test
	public void test2_DP1andDP2() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(1));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//triggers attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule2");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule2"));
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule2");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule2"));

		//check since last attack
		generateEvents(sleepAmount, detectionPoint1, 1, "rule2");
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule2"));
		generateEvents(sleepAmount, detectionPoint2, 1, "rule2");
		assertEventsAndAttacks(13, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule2"));

		//triggers attack in reverse
		generateEvents(sleepAmount*11, detectionPoint2, 11, "rule2");
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule2"));

		generateEvents(sleepAmount*2, detectionPoint1, 2, "rule2");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule2"));
	}

	@Test
	public void test3_DP1orDP2() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(2));;

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//triggers attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule3");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule3"));

		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule3");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule3"));

		//check since last attack
		generateEvents(sleepAmount, detectionPoint1, 1, "rule3");
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule3"));

		generateEvents(sleepAmount, detectionPoint2, 1, "rule3");
		assertEventsAndAttacks(13, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule3"));

		//triggers attack in reverse order
		generateEvents(sleepAmount*11, detectionPoint2, 11, "rule3");
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 3, criteria.get("rule3"));

		//won't trigger because attack already happened
		generateEvents(sleepAmount*2, detectionPoint1, 2, "rule3");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 3, criteria.get("rule3"));

		//now it will trigger
		generateEvents(sleepAmount*2, detectionPoint1, 1, "rule3");
		assertEventsAndAttacks(7, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 4, criteria.get("rule3"));
	}

	@Test
	public void test4_DP1orDP2andDP3() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(3));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule4");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule4"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule4");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule4"));

		//DP3 AND DP2 - trigger attack
		generateEvents(sleepAmount*13, detectionPoint3, 13, "rule4");
		assertEventsAndAttacks(13, 1, criteria.get("dp3"));
		assertEventsAndAttacks(0, 2, criteria.get("rule4"));

		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule4");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 3, criteria.get("rule4"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule4");
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 4, criteria.get("rule4"));
	}

	@Test
	public void test5_DP1thenDP2() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(4));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule5");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule5"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule5");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule5"));

		//DP2 - no attack
		generateEvents(sleepAmount*11, detectionPoint2, 11, "rule5");
		assertEventsAndAttacks(23, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule5"));

		generateEvents(sleepAmount*1, detectionPoint2, 1, "rule5");
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule5"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule5");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule5"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule5");
		assertEventsAndAttacks(36, 3, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule5"));
	}

	@Test
	public void test6_DP1thenDP2thenDP1orDP2() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(5));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		clearStores();

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP3 - no attack
		generateEvents(sleepAmount*13, detectionPoint3, 13, "rule6");
		assertEventsAndAttacks(13, 1, criteria.get("dp3"));
		assertEventsAndAttacks(0, 0, criteria.get("rule6"));

		//DP2 - attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(36, 3, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule6");
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(48, 4, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule6"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12, "rule6");
		assertEventsAndAttacks(60, 5, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule6"));
	}

	//assumes no rules will be triggered until last event
	private void generateEvents (int time, DetectionPoint detectionPoint, int eventCount, String ruleName) throws Exception {
		int attackCount = appSensorServer.getAttackStore().findAttacks(criteria.get(ruleName)).size();

		for (int i = 0; i < eventCount; i++) {
			assertEquals(attackCount, appSensorServer.getAttackStore().findAttacks(criteria.get(ruleName)).size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint, new DetectionSystem("localhostme")));
			Thread.sleep(time/eventCount);
		}
	}

	private void assertEventsAndAttacks (int eventCount, int attackCount, SearchCriteria criteria) {
		if (criteria.getRule() == null) {
			assertEquals(eventCount, appSensorServer.getEventStore().findEvents(criteria).size());
		}
		assertEquals(attackCount, appSensorServer.getAttackStore().findAttacks(criteria).size());
	}

	private void setRule(AppSensorServer server, Rule rule) {
		Collection<Rule> rules = new ArrayList<Rule>();
		rules.add(rule);
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setRules(rules);
		appSensorServer.setConfiguration(updatedConfiguration);
	}

	private void clearStores() {
		((InMemoryAttackStore) appSensorServer.getAttackStore()).clearAll();
		((InMemoryEventStore) appSensorServer.getEventStore()).clearAll();
	}

	private static ArrayList<Rule> generateRules() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		// intervals
		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes6 = new Interval(6, Interval.MINUTES);
		Interval minutes16 = new Interval(16, Interval.MINUTES);

		// detection points
		RulesDetectionPoint point1 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(3, minutes5)));
		RulesDetectionPoint point2 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", new Threshold(12, minutes5)));
		RulesDetectionPoint point3 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", new Threshold(13, minutes6)));

		// clauses
		ArrayList<RulesDetectionPoint> points1 = new ArrayList<RulesDetectionPoint>();
		points1.add(point1);
		ArrayList<RulesDetectionPoint> points1and2 = new ArrayList<RulesDetectionPoint>();
		points1and2.add(point1);
		points1and2.add(point2);
		ArrayList<RulesDetectionPoint> points2 = new ArrayList<RulesDetectionPoint>();
		points2.add(point2);
		ArrayList<RulesDetectionPoint> points2and3 = new ArrayList<RulesDetectionPoint>();
		points2and3.add(point2);
		points2and3.add(point3);

		Clause clause1 = new Clause(points1);
		Clause clause1and2 = new Clause(points1and2);
		Clause clause2 = new Clause(points2);
		Clause clause2and3 = new Clause(points2and3);

		// responses
		ArrayList<Response> responses = generateResponses();

		//rule 1: DP1
		ArrayList<Clause> clauses1 = new ArrayList<Clause>();
		clauses1.add(clause1);

		org.owasp.appsensor.core.rule.Expression expression1 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1.add(expression1);

		configuredRules.add(new Rule("Rule 1", minutes5, expressions1, responses));

		//rule 2: DP1 AND DP2
		ArrayList<Clause> clauses1and2 = new ArrayList<Clause>();
		clauses1and2.add(clause1and2);

		org.owasp.appsensor.core.rule.Expression expression1and2 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1and2);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1and2 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1and2.add(expression1and2);

		configuredRules.add(new Rule("Rule 2", minutes5, expressions1and2, responses));

		//rule 3: DP1 OR DP2
		ArrayList<Clause> clauses1or2 = new ArrayList<Clause>();
		clauses1or2.add(clause1);
		clauses1or2.add(clause2);

		org.owasp.appsensor.core.rule.Expression expression1or2 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1or2);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1or2 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1or2.add(expression1or2);

		configuredRules.add(new Rule("Rule 3", minutes5, expressions1or2, responses));

		//rule4: DP1 OR DP2 AND DP3
		ArrayList<Clause> clauses1or2and3 = new ArrayList<Clause>();
		clauses1or2and3.add(clause1);
		clauses1or2and3.add(clause2and3);

		org.owasp.appsensor.core.rule.Expression expression1or2and3 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1or2and3);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1or2and3 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1or2and3.add(expression1or2and3);

		configuredRules.add(new Rule("Rule 4", minutes5, expressions1or2and3, responses));

		//rule 5: DP1 THEN DP2
		ArrayList<Clause> clauses2 = new ArrayList<Clause>();
		clauses2.add(clause2);

		org.owasp.appsensor.core.rule.Expression expression2 = new org.owasp.appsensor.core.rule.Expression(minutes6, clauses2);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1then2 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1then2.add(expression1);
		expressions1then2.add(expression2);

		configuredRules.add(new Rule("Rule 5", minutes6, expressions1then2, responses));

		//rule 6: DP1 THEN DP2 THEN DP1 OR DP2
		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1then2then1or2 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1then2then1or2.add(expression1);
		expressions1then2then1or2.add(expression2);
		expressions1then2then1or2.add(expression1or2);

		configuredRules.add(new Rule("Rule 7", minutes16, expressions1then2then1or2, responses));

		return configuredRules;
	}

	private static Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		ArrayList<Response> responses = generateResponses();

		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes6 = new Interval(6, Interval.MINUTES);

		Threshold events3minutes5 = new Threshold(3, minutes5);
		Threshold events12minutes5 = new Threshold(12, minutes5);
		Threshold events13minutes6 = new Threshold(13, minutes6);

		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events3minutes5, responses);
		DetectionPoint point2 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", events12minutes5, responses);
		DetectionPoint point3 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", events13minutes6, responses);

		configuredDetectionPoints.add(point1);
		configuredDetectionPoints.add(point2);
		configuredDetectionPoints.add(point3);

		return configuredDetectionPoints;
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

}
