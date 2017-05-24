package org.owasp.appsensor.local.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

import javax.inject.Inject;

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
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.core.rule.MonitorPoint;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Basic test for the {@link AggregateEventAnalysisEngine}.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class SimpleAggregateEventAnalysisEngineTest {

	private static User bob = new User("bob");

	private static DetectionPoint detectionPoint1 = new DetectionPoint();

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

		detectionSystems1.add(detectionSystem1.getDetectionSystemId());

		criteria.put("all", new SearchCriteria().setDetectionSystemIds(detectionSystems1));

		criteria.put("dp1", new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1));

		rules = generateRules();

		criteria.put("rule1", new SearchCriteria().
				setUser(bob).
				setRule(rules.get(0)).
				setDetectionSystemIds(detectionSystems1));
	}

	@Before
	public void initializeTest() {
		if (myEngine == null) {
			initialSetup();
		}

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

		setRule(appSensorServer, null);
	}

	@Test
	public void test1_DP1() throws Exception {
		//Add rule
		setRule(appSensorServer, rules.get(0));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		// 3 events and triggered attack
		generateEvents(sleepAmount*3, detectionPoint1, 3, "rule1");
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

		// 1 event and no new attack
		generateEvents(sleepAmount, detectionPoint1, 1, "rule1");
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEquals(1, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

		// 2 events and 2 total attack
		generateEvents(sleepAmount*2, detectionPoint1, 2, "rule1");
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEquals(2, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());
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

	private static ArrayList<Rule> generateRules() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		// intervals
		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes16 = new Interval(16, Interval.MINUTES);

		// detection points
		MonitorPoint point1 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(3, minutes5)));
		point1.setGuid("00000000-0000-0000-0000-000000000000");

		// clauses
		ArrayList<DetectionPoint> points1 = new ArrayList<DetectionPoint>();
		points1.add(point1);

		Clause clause1 = new Clause(points1);

		// responses
		ArrayList<Response> responses = generateResponses();

		//rule 1: DP1
		ArrayList<Clause> clauses1 = new ArrayList<Clause>();
		clauses1.add(clause1);

		org.owasp.appsensor.core.rule.Expression expression1 = new org.owasp.appsensor.core.rule.Expression(minutes5, clauses1);

		ArrayList<org.owasp.appsensor.core.rule.Expression> expressions1 = new ArrayList<org.owasp.appsensor.core.rule.Expression>();
		expressions1.add(expression1);

		configuredRules.add(new Rule("00000000-0000-0000-0000-000000000011", minutes16, expressions1, responses, "Rule 1"));

		return configuredRules;
	}

	private static Collection<DetectionPoint> loadMockedDetectionPoints() {
		final Collection<DetectionPoint> configuredDetectionPoints = new ArrayList<DetectionPoint>();

		ArrayList<Response> responses = generateResponses();

		Interval minutes5 = new Interval(5, Interval.MINUTES);

		Threshold events3minutes5 = new Threshold(3, minutes5);

		DetectionPoint point1 = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", events3minutes5, responses);

		configuredDetectionPoints.add(point1);

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