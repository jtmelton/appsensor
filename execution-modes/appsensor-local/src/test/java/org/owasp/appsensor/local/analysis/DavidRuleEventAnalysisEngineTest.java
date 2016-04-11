package org.owasp.appsensor.local.analysis; 

import static org.junit.Assert.assertEquals;

import java.beans.Expression;
import java.util.ArrayList;
import java.util.Collection;

import javax.inject.Inject;
import javax.print.attribute.standard.MediaSize.Engineering;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.owasp.appsensor.analysis.DavidAttackAnalysisEngine;
import org.owasp.appsensor.analysis.DavidEventAnalysisEngine;
import org.owasp.appsensor.analysis.DetectionPointVariable;
import org.owasp.appsensor.analysis.Rule;
import org.owasp.appsensor.analysis.RulesDetectionPoint;
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
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.criteria.SearchCriteria;
import org.springframework.expression.spel.ExpressionState;
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
	
	private static Collection<String> detectionSystems1 = new ArrayList<String>();
	
	private static DetectionSystem detectionSystem1 = new DetectionSystem("localhostme");
	
	protected int sleepAmount = 1;
	
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
		
		detectionSystems1.add(detectionSystem1.getDetectionSystemId());
	}
	
	@Test
	public void testOneDetectionPoint() throws Exception {
		//instantiate server
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);
		
		//DP1
		Rule rule1 = generateRule1().get(0);
		
		//prepare rule
		((DavidEventAnalysisEngine)appSensorServer.getEventAnalysisEngine()).clearRules();
		((DavidEventAnalysisEngine)appSensorServer.getEventAnalysisEngine()).addRule(rule1);

		SearchCriteria criteria = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1);
		
		//generate events
		eventAndAssert(sleepAmount, 0, null, 0, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 1, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 2, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 3, 1, criteria);
	}
	
	@Test
	public void testTwoDetectionPoints() throws Exception {
		//instantiate server
		ServerConfiguration updatedConfiguration = appSensorServer.getConfiguration();
		updatedConfiguration.setDetectionPoints(loadMockedDetectionPoints());
		appSensorServer.setConfiguration(updatedConfiguration);
		
		//DP1 AND DP2
		Rule rule2 = generateRule2().get(0);
		
		//prepare rule
		((DavidEventAnalysisEngine)appSensorServer.getEventAnalysisEngine()).clearRules();
		((DavidEventAnalysisEngine)appSensorServer.getEventAnalysisEngine()).addRule(rule2);

		SearchCriteria criteria = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint1).
				setDetectionSystemIds(detectionSystems1);
		
		SearchCriteria criteria2 = new SearchCriteria().
				setUser(bob).
				setDetectionPoint(detectionPoint2).
				setDetectionSystemIds(detectionSystems1);
		
		//generate events
		eventAndAssert(sleepAmount, 0, null, 0, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 1, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 2, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint1, 3, 0, criteria);
		eventAndAssert(sleepAmount, 1, detectionPoint2, 1, 0, criteria2);
		eventAndAssert(sleepAmount, 11, detectionPoint2, 12, 1, criteria2);
	}
		
	public void eventAndAssert(int sleepTime, int runNumEvents, DetectionPoint detectionPoint, int isNumEvents, int isNumAttacks, SearchCriteria criteria) throws Exception{
		
		if (detectionPoint != null) {
			for (int i = 0; i < runNumEvents; i++) {
				appSensorClient.getEventManager().addEvent(new Event(bob, detectionPoint, new DetectionSystem("localhostme")));
			}
		}
		
		Thread.sleep(sleepTime);
		
		assertEquals(isNumEvents, appSensorServer.getEventStore().findEvents(criteria).size());
		assertEquals(isNumAttacks, appSensorServer.getAttackStore().findAttacks(criteria).size());
	}
	
	private ArrayList<Rule> generateRule1() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		Interval minutes5 = new Interval(5, Interval.MINUTES);
		
		//detection point
		DetectionPoint point1 = createDetectionPoint("IE1", 3, 5);

		//rule
		DetectionPointVariable detectionPointVariable = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point1);
		ArrayList<DetectionPointVariable> detectionPointVariables = new ArrayList<DetectionPointVariable>();
		detectionPointVariables.add(detectionPointVariable);
		
		org.owasp.appsensor.analysis.Expression expression = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions.add(expression);
		
		Rule rule = new Rule(minutes5, expressions);
		configuredRules.add(rule);
		
		return configuredRules;
	}
	
	private ArrayList<Rule> generateRule2() {
		final ArrayList<Rule> configuredRules = new ArrayList<Rule>();
		Interval minutes5 = new Interval(15, Interval.MINUTES);
		
		//detection point
		DetectionPoint point1 = createDetectionPoint("IE1", 3, 5);
		DetectionPoint point2 = createDetectionPoint("IE2", 12, 5);

		//rule: DP1 AND DP2
		DetectionPointVariable detectionPointVariable1 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point1);
		DetectionPointVariable detectionPointVariable2 = new DetectionPointVariable(DetectionPointVariable.BOOLEAN_OPERATOR_AND, point2);
		ArrayList<DetectionPointVariable> detectionPointVariables = new ArrayList<DetectionPointVariable>();
		detectionPointVariables.add(detectionPointVariable1);
		detectionPointVariables.add(detectionPointVariable2);
		
		org.owasp.appsensor.analysis.Expression expression = new org.owasp.appsensor.analysis.Expression(minutes5, detectionPointVariables);
		ArrayList<org.owasp.appsensor.analysis.Expression> expressions = new ArrayList<org.owasp.appsensor.analysis.Expression>();
		expressions.add(expression);
		
		Rule rule = new Rule(minutes5, expressions);
		configuredRules.add(rule);
		
		return configuredRules;
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
	
	private DetectionPoint createDetectionPoint(String label, int events, int minutes) {
		DetectionPoint point = null;
		
		Response log = new Response();
		log.setAction("log");
		
		Response logout = new Response();
		logout.setAction("logout");
		
		Response disableUser = new Response();
		disableUser.setAction("disableUser");
		
		Collection<Response> point1Responses = new ArrayList<Response>();
		point1Responses.add(log);
		point1Responses.add(logout);
		point1Responses.add(disableUser);
		
		Interval interval = new Interval(minutes, Interval.MINUTES);
		
		Threshold threshold = new Threshold(events, interval);
		
		point = new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, label, threshold, point1Responses);
		
		return point;
	}
}
