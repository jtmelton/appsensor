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
import org.owasp.appsensor.analysis.DetectionPointVariable;
import org.owasp.appsensor.analysis.Rule;
//import org.owasp.appsensor.analysis.Expression;
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
 * Test basic {@link Event} analysis engine. Add a number of {@link Event}s matching
 * the known set of criteria and ensure the {@link Attack}s are triggered at
 * the appropriate points.
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 * @author Raphaël Taban
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class DavidRuleEventAnalysisEngineTest {

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

		detectionPoint2.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint2.setLabel("IE2");

		detectionPoint3.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint3.setLabel("IE3");

		detectionPoint5.setCategory(DetectionPoint.Category.INPUT_VALIDATION);
		detectionPoint5.setLabel("IE5");

		detectionSystems1.add(detectionSystem1.getDetectionSystemId());

		criteria.put("all", new SearchCriteria().setDetectionSystemIds(detectionSystems1));

		criteria.put("rule", new SearchCriteria().setUser(new User("bobR")));

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

		clearStores();
	}

	@Test
	public void test1_DP1() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(0));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		generateEvents(sleepAmount, detectionPoint1, 1);
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));
	}

	@Test
	public void test2_DP1andDP2() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(1));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//triggers attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//check since last attack
		generateEvents(sleepAmount, detectionPoint1, 1);
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));
		generateEvents(sleepAmount, detectionPoint2, 1);
		assertEventsAndAttacks(13, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//triggers attack in reverse
		generateEvents(sleepAmount*11, detectionPoint2, 11);
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		generateEvents(sleepAmount*2, detectionPoint1, 2);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));
	}

	@Test
	public void test3_DP1orDP2() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(2));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//triggers attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));

		//check since last attack
		generateEvents(sleepAmount, detectionPoint1, 1);
		assertEventsAndAttacks(4, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));

		generateEvents(sleepAmount, detectionPoint2, 1);
		assertEventsAndAttacks(13, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));

		//triggers attack in reverse order
		generateEvents(sleepAmount*11, detectionPoint2, 11);
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 3, criteria.get("rule"));

		//won't trigger because attack already happened
		generateEvents(sleepAmount*2, detectionPoint1, 2);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 3, criteria.get("rule"));

		//now it will trigger
		generateEvents(sleepAmount*2, detectionPoint1, 1);
		assertEventsAndAttacks(7, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 4, criteria.get("rule"));
	}

	@Test
	public void test4_DP1andnotDP2() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(3));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP2 and DP1 - no attack triggered
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		clearStores();

		//DP1 and no DP2 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP2 and DP1 - no attack triggered
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));
	}

	@Test
	public void test5_DP1orDP2andnotDP3() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(4));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));

		//DP2 AND NOT DP3 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 3, criteria.get("rule"));

		//DP3 AND DP2 - no attack
		generateEvents(sleepAmount*13, detectionPoint3, 13);
		assertEventsAndAttacks(13, 1, criteria.get("dp3"));
		assertEventsAndAttacks(0, 3, criteria.get("rule"));

		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 3, criteria.get("rule"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 4, criteria.get("rule"));
	}

	@Test
	public void test6_DP1thenDP2() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(5));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*11, detectionPoint2, 11);
		assertEventsAndAttacks(23, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		generateEvents(sleepAmount*1, detectionPoint2, 1);
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(36, 3, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));
	}

	@Test
	public void test7_DP1thenDP2thenDP1orDP2andnotDP3() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(6));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		clearStores();

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(24, 2, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP3 - no attack
		generateEvents(sleepAmount*13, detectionPoint3, 13);
		assertEventsAndAttacks(13, 1, criteria.get("dp3"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(36, 3, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP1 - trigger attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(6, 2, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(9, 3, criteria.get("dp1"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(48, 4, criteria.get("dp2"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));

		//DP2 - trigger attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(60, 5, criteria.get("dp2"));
		assertEventsAndAttacks(0, 2, criteria.get("rule"));
	}

	/*
	@Test
	public void test8_DP1thenDP2thennotDP3thennotDP4thenDP5() throws Exception {
		//Add rule
		myEngine.addRule(rules.get(7));

		//is empty
		assertEventsAndAttacks(0, 0, criteria.get("all"));

		//DP1 - no attack
		generateEvents(sleepAmount*3, detectionPoint1, 3);
		assertEventsAndAttacks(3, 1, criteria.get("dp1"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP2 - no attack
		generateEvents(sleepAmount*12, detectionPoint2, 12);
		assertEventsAndAttacks(12, 1, criteria.get("dp2"));
		assertEventsAndAttacks(0, 0, criteria.get("rule"));

		//DP5 - attack
		generateEvents(sleepAmount*15, detectionPoint5, 15);
		assertEventsAndAttacks(15, 1, criteria.get("dp5"));
		assertEventsAndAttacks(0, 1, criteria.get("rule"));
	}
	*/

	//assumes no rules will be triggered until last event
	private void generateEvents (int time, DetectionPoint detectionPoint, int eventCount) throws Exception {
		int attackCount = appSensorServer.getAttackStore().findAttacks(criteria.get("rule")).size();

		for (int i = 0; i < eventCount; i++) {
			assertEquals(attackCount, appSensorServer.getAttackStore().findAttacks(criteria.get("rule")).size());
			appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint, new DetectionSystem("localhostme")));
			Thread.sleep(time/eventCount);
		}
	}

	private void assertEventsAndAttacks (int eventCount, int attackCount, SearchCriteria criteria) {
		assertEquals(eventCount, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(attackCount, appSensorServer.getAttackStore().findAttacks(criteria).size());
	}

	private void clearStores() {
		((InMemoryAttackStore) appSensorServer.getAttackStore()).clearAll();
		((InMemoryEventStore) appSensorServer.getEventStore()).clearAll();
	}

	private static ArrayList<Rule> generateRules() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		Interval minutes5 = new Interval(5, Interval.MINUTES);
		Interval minutes6 = new Interval(6, Interval.MINUTES);
		Interval minutes10 = new Interval(10, Interval.MINUTES);
		Interval minutes14 = new Interval(14, Interval.MINUTES);
		Interval minutes15 = new Interval(15, Interval.MINUTES);
		Interval minutes16 = new Interval(16, Interval.MINUTES);

		//detection points
		DetectionPoint point1 = createDetectionPoint("IE1", 3, 5);
		DetectionPoint point2 = createDetectionPoint("IE2", 12, 5);
		DetectionPoint point3 = createDetectionPoint("IE3", 13, 6);
		DetectionPoint point4 = createDetectionPoint("IE4", 14, 7);
		DetectionPoint point5 = createDetectionPoint("IE5", 15, 8);

		DetectionPointVariable detectionPointVariable1 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point1);
		DetectionPointVariable detectionPointVariable2 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point2);
		DetectionPointVariable detectionPointVariable3 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_OR, point2);
		DetectionPointVariable detectionPointVariable4 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT, point2);
		DetectionPointVariable detectionPointVariable5 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT, point3);
		DetectionPointVariable detectionPointVariable6 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND_NOT, point4);
		DetectionPointVariable detectionPointVariable7 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point5);

		//rule 1: DP1
		ArrayList<DetectionPointVariable> detectionPointVariables1 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables1.add(detectionPointVariable1);

		org.owasp.appsensor.analysis.Expression expression1 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables1);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions1 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions1.add(expression1);

		configuredRules.add(new Rule("Rule 1", minutes5, expressions1));

		//rule 2: DP1 AND DP2
		ArrayList<DetectionPointVariable> detectionPointVariables2 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables2.add(detectionPointVariable1);
		detectionPointVariables2.add(detectionPointVariable2);

		org.owasp.appsensor.analysis.Expression expression2 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables2);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions2 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions2.add(expression2);

		configuredRules.add(new Rule("Rule 2", minutes5, expressions2));

		//rule 3: DP1 OR DP2
		ArrayList<DetectionPointVariable> detectionPointVariables3 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables3.add(detectionPointVariable1);
		detectionPointVariables3.add(detectionPointVariable3);

		org.owasp.appsensor.analysis.Expression expression3 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables3);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions3 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions3.add(expression3);

		configuredRules.add(new Rule("Rule 3", minutes5, expressions3));

		//rule 4: DP1 AND NOT DP2
		ArrayList<DetectionPointVariable> detectionPointVariables4 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables4.add(detectionPointVariable1);
		detectionPointVariables4.add(detectionPointVariable4);

		org.owasp.appsensor.analysis.Expression expression4 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables4);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions4 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions4.add(expression4);

		configuredRules.add(new Rule("Rule 4", minutes5, expressions4));

		//rule5: DP1 OR DP2 AND NOT DP3
		ArrayList<DetectionPointVariable> detectionPointVariables5 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables5.add(detectionPointVariable1);
		detectionPointVariables5.add(detectionPointVariable3);
		detectionPointVariables5.add(detectionPointVariable5);

		org.owasp.appsensor.analysis.Expression expression5 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables5);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions5 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions5.add(expression5);

		configuredRules.add(new Rule("Rule 5", minutes6, expressions5));

		//rule 6: DP1 THEN DP2
		ArrayList<DetectionPointVariable> detectionPointVariables6 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables6.add(detectionPointVariable2);

		org.owasp.appsensor.analysis.Expression expression6 = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables6);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions6 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions6.add(expression1);
		expressions6.add(expression6);

		configuredRules.add(new Rule("Rule 6", minutes10, expressions6));

		//rule 7: DP1 THEN DP2 THEN DP1 OR DP2 AND NOT DP3
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions7 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions7.add(expression1);
		expressions7.add(expression6);
		expressions7.add(expression5);

		configuredRules.add(new Rule("Rule 7", minutes16, expressions7));

		//rule 8: DP1 THEN DP2 THEN NOT DP3 THEN NOT DP4 THEN DP5
		//are all the expression times supposed to add up to the rule time?
		//do you set a time for an only "AND NOT" expression? - NO!
			//NO "AND NOT" expressions. For now.
		ArrayList<DetectionPointVariable> detectionPointVariables7 = new ArrayList<DetectionPointVariable>();
		ArrayList<DetectionPointVariable> detectionPointVariables8 = new ArrayList<DetectionPointVariable>();
		ArrayList<DetectionPointVariable> detectionPointVariables9 = new ArrayList<DetectionPointVariable>();
		detectionPointVariables7.add(detectionPointVariable5);
		detectionPointVariables8.add(detectionPointVariable6);
		detectionPointVariables9.add(detectionPointVariable7);

		org.owasp.appsensor.analysis.Expression expression7 = new org.owasp.appsensor.analysis.Expression(minutes14, detectionPointVariables7);
		org.owasp.appsensor.analysis.Expression expression8 = new org.owasp.appsensor.analysis.Expression(minutes15, detectionPointVariables8);
		org.owasp.appsensor.analysis.Expression expression9 = new org.owasp.appsensor.analysis.Expression(minutes14, detectionPointVariables9);

		ArrayList<org.owasp.appsensor.analysis.Expression> expressions8 = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions8.add(expression1);
		expressions8.add(expression6);
		expressions8.add(expression7);
		expressions8.add(expression8);
		expressions8.add(expression9);

		configuredRules.add(new Rule("Rule 8", minutes16, expressions8));

		return configuredRules;
	}

	private static Collection<DetectionPoint> loadMockedDetectionPoints() {
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

	private static DetectionPoint createDetectionPoint(String label, int events, int minutes) {
		DetectionPoint point = null;

		Interval interval = new Interval(minutes, Interval.MINUTES);

		Threshold threshold = new Threshold(events, interval);

		point = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, label, threshold, null);

		return point;
	}

/*
	private static ArrayList<Rule> getRules(String filename) {
		ArrayList<Rule> rules = null;

		ObjectMapper mapper = new ObjectMapper();
		try {
			rules = (ArrayList<Rule>) Arrays.asList(mapper.readValue(new File("/home/david/Desktop/" + filename), Rule[].class));
			System.out.println(rules);
		} catch (Exception e) {
			System.out.println(e);
		}

		return rules;
	}

	private static void writeRules(String filename, ArrayList<Rule> rules) {
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(SerializationFeature.INDENT_OUTPUT, true);

		try {
			mapper.writeValue(new File("/home/david/Desktop/" + filename), rules);
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	private static Rule createRuleFromJson(String json) {
		JSONObject jsonRule = new JSONObject(json);
		Rule rule = new Rule();
		//rule.duration = jsonRule.getJSONObject("duration");

		for (JSONObject jsonExpression : jsonRule.getJSONObject("expressions")) {

			Expression exp = new Expression();
			//exp.duration = jsonExpression.getJSONObject("duration");

			for (JSONObject jsonDpv : jsonExpression.getJSONObject("dpvs")) {

				DetectionPointVariable dpv = new DetectionPointVariable(DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, dpv.getJSONObject("label"), new Threshold(dpv.getJSONObject("count"), new Interval(dpv.getJSONObject("duration"), Interval.MINUTES)), null), dpv.getJSONObject("oper"));

				//exp.addDPV(dpv)
			}
			//rule.addExpression(exp);
		}

		return rule;
	}
	*/
}
