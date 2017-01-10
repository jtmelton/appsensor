package org.owasp.appsensor.configuration.stax.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Iterator;

import org.junit.Test;
import org.owasp.appsensor.configuration.stax.server.StaxServerConfigurationReader;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.Response;
import org.owasp.appsensor.core.Threshold;
import org.owasp.appsensor.core.configuration.server.ServerConfiguration;
import org.owasp.appsensor.core.configuration.server.ServerConfigurationReader;
import org.owasp.appsensor.core.exceptions.ConfigurationException;
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.Expression;
import org.owasp.appsensor.core.rule.MonitorPoint;
import org.owasp.appsensor.core.rule.Rule;

/**
 * Test various configuration settings from the xml server configuration
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
//@RunWith(SpringJUnit4ClassRunner.class)
//@ContextConfiguration(locations={"classpath:base-context.xml"})
public class XmlServerConfigurationReaderTest {

	@Test
	public void testConfigLoad() throws Exception {
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-config.xml", "/appsensor_server_config_2.0.xsd");

		assertEquals("X-Appsensor-Client-Application-Name2", configuration.getClientApplicationIdentificationHeaderName());
	}

	@Test
	public void testStandardRulesLoad() throws Exception{
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-rules-standard-config.xml", "/appsensor_server_config_2.0.xsd");

		// assert exists
		assertEquals("X-Appsensor-Client-Application-Standard-Rules", configuration.getClientApplicationIdentificationHeaderName());

		// assert all rule components are as expected
		// monitor points
		ArrayList<DetectionPoint> monitorPoints = new ArrayList<DetectionPoint>();
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(5, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000001"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(3, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000002"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", new Threshold(5, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000003"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", new Threshold(10, new Interval(3, Interval.MINUTES))), "00000000-0000-0000-0000-000000000004"));

		for (DetectionPoint point : monitorPoints) {
			assertTrue("Failed on MonitorPoint: " + point.toString(), configuration.getRules().iterator().next().getAllDetectionPoints().contains(point));
		}

		// clauses
		ArrayList<Clause> clauses = new ArrayList<Clause>();
		clauses.add(new Clause(monitorPoints.subList(0, 2)));
		clauses.add(new Clause(monitorPoints.subList(2, 3)));
		clauses.add(new Clause(monitorPoints.subList(3, 4)));

		ArrayList<Clause> configuredClauses = new ArrayList<Clause>();
		for (Expression expression : configuration.getRules().iterator().next().getExpressions()) {
			configuredClauses.addAll(expression.getClauses());
		}

		for (Clause clause : clauses) {
			assertTrue("Failed on Clause: " + clause.toString(), configuredClauses.contains(clause));
		}

		// expressions
		ArrayList<Expression> expressions = new ArrayList<Expression>();
		expressions.add(new Expression(new Interval(2, Interval.MINUTES), clauses.subList(0,2)));
		expressions.add(new Expression(new Interval(3, Interval.MINUTES), clauses.subList(2,3)));

		for (Expression expression : expressions) {
			assertTrue("Failed on Expression: " + expression.toString(), configuration.getRules().iterator().next().getExpressions().contains(expression));
		}

		// rule
		ArrayList<Response> responses = new ArrayList<Response>();
		responses.add(new Response().setAction("log"));
		responses.add(new Response().setAction("logout"));
		responses.add(new Response().setAction("disableUser"));
		responses.add(new Response().setAction("disableComponentForSpecificUser").setInterval(new Interval(30, Interval.MINUTES)));
		responses.add(new Response().setAction("disableComponentForAllUsers").setInterval(new Interval(30, Interval.MINUTES)));

		Rule rule = new Rule("00000000-0000-0000-0000-000000000000", new Interval(5, Interval.MINUTES), expressions, responses);

		assertTrue("Failed on Rule: " + rule.toString(), configuration.getRules().iterator().next().equals(rule));
	}

	@Test
	public void testMultipleStandardRulesLoad() throws Exception{
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-rules-standard-multiple-config.xml", "/appsensor_server_config_2.0.xsd");

		Iterator<Rule> rules = configuration.getRules().iterator();
		Rule configuredRule = rules.next();

		// assert exists
		assertEquals("X-Appsensor-Client-Application-Multiple-Standard-Rules", configuration.getClientApplicationIdentificationHeaderName());

		// check rule 1
		// monitor points
		ArrayList<DetectionPoint> monitorPoints = new ArrayList<DetectionPoint>();
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(5, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000001"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1", new Threshold(3, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000002"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2", new Threshold(5, new Interval(1, Interval.MINUTES))), "00000000-0000-0000-0000-000000000003"));
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", new Threshold(10, new Interval(3, Interval.MINUTES))), "00000000-0000-0000-0000-000000000004"));

		for (DetectionPoint point : monitorPoints) {
			assertTrue("Failed on MonitorPoint: " + point.toString(), configuredRule.getAllDetectionPoints().contains(point));
		}

		// clauses
		ArrayList<Clause> clauses = new ArrayList<Clause>();
		clauses.add(new Clause(monitorPoints.subList(0, 2)));
		clauses.add(new Clause(monitorPoints.subList(2, 3)));
		clauses.add(new Clause(monitorPoints.subList(3, 4)));

		ArrayList<Clause> configuredClauses = new ArrayList<Clause>();
		for (Expression expression : configuration.getRules().iterator().next().getExpressions()) {
			configuredClauses.addAll(expression.getClauses());
		}

		for (Clause clause : clauses) {
			assertTrue("Failed on Clause: " + clause.toString(), configuredClauses.contains(clause));
		}

		// expressions
		ArrayList<Expression> expressions = new ArrayList<Expression>();
		expressions.add(new Expression(new Interval(2, Interval.MINUTES), clauses.subList(0,2)));
		expressions.add(new Expression(new Interval(3, Interval.MINUTES), clauses.subList(2,3)));

		for (Expression expression : expressions) {
			assertTrue("Failed on Expression: " + expression.toString(), configuredRule.getExpressions().contains(expression));
		}

		// rule
		ArrayList<Response> responses = new ArrayList<Response>();
		responses.add(new Response().setAction("log"));
		responses.add(new Response().setAction("logout"));
		responses.add(new Response().setAction("disableUser"));
		responses.add(new Response().setAction("disableComponentForSpecificUser").setInterval(new Interval(30, Interval.MINUTES)));
		responses.add(new Response().setAction("disableComponentForAllUsers").setInterval(new Interval(30, Interval.MINUTES)));

		Rule rule = new Rule(null, new Interval(5, Interval.MINUTES), expressions);
		rule.setResponses(responses);
		rule.setGuid("00000000-0000-0000-0000-000000000000");
		rule.setName("Rule 1");

		assertTrue("Failed on Rule: " + rule.toString(), configuredRule.equals(rule));

		// check rule 2
		assertTrue(rules.hasNext());
		configuredRule = rules.next();

		// monitor points
		monitorPoints = new ArrayList<DetectionPoint>();
		monitorPoints.add(new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3", new Threshold(10, new Interval(3, Interval.MINUTES))), "00000000-0000-0000-0000-000000000006"));

		for (DetectionPoint point : monitorPoints) {
			assertTrue("Failed on MonitorPoint: " + point.toString(), configuredRule.getAllDetectionPoints().contains(point));
		}

		// clauses
		clauses = new ArrayList<Clause>();
		clauses.add(new Clause(monitorPoints));

		configuredClauses = new ArrayList<Clause>();
		for (Expression expression : configuredRule.getExpressions()) {
			configuredClauses.addAll(expression.getClauses());
		}

		for (Clause clause : clauses) {
			assertTrue("Failed on Clause: " + clause.toString(), configuredClauses.contains(clause));
		}

		// expressions
		expressions = new ArrayList<Expression>();
		expressions.add(new Expression(new Interval(3, Interval.MINUTES), clauses));

		for (Expression expression : expressions) {
			assertTrue("Failed on Expression: " + expression.toString(), configuredRule.getExpressions().contains(expression));
		}

		// rule
		responses = new ArrayList<Response>();
		responses.add(new Response().setAction("log"));

		rule = new Rule(null, new Interval(5, Interval.MINUTES), expressions);
		rule.setResponses(responses);
		rule.setGuid("00000000-0000-0000-0000-000000000005");
		rule.setName("Rule 2");

		assertTrue("Failed on Rule: " + rule.toString(), configuredRule.equals(rule));
	}

	@Test
	public void testStandardRulesLoadWithDetectionPoints() throws Exception{
		ServerConfigurationReader reader = new StaxServerConfigurationReader();
		ServerConfiguration configuration = reader.read("/appsensor-server-rules-standard-config-with-detection-points.xml", "/appsensor_server_config_2.0.xsd");

		Iterator<Rule> rules = configuration.getRules().iterator();
		Rule configuredRule = rules.next();

		// assert exists
		assertEquals("X-Appsensor-Client-Application-Standard-Rules-With-Detection-Points", configuration.getClientApplicationIdentificationHeaderName());

		// check if it has rule
		assertEquals(configuredRule.getGuid(), "00000000-0000-0000-0000-000000000000");

		// check if it has detection point
		assertEquals(configuration.getDetectionPoints().iterator().next().getLabel(), "IE1");
	}

	@Test
	public void testInvalidRulesLoadExpressionsLongerThanRules() throws Exception{
		try {
			ServerConfigurationReader reader = new StaxServerConfigurationReader();
			reader.read("/appsensor-server-rules-invalid-expression-window-config.xml", "/appsensor_server_config_2.0.xsd");
		}
		catch (ConfigurationException exception){
			assertTrue(exception.toString().startsWith("org.owasp.appsensor.core.exceptions.ConfigurationException: Incompatible windows set in rule: "));
			return;
		}
		fail();
	}

	@Test
	public void testInvalidRulesLoadDetectionPointsLongerThanExpression() throws Exception{
		try {
			ServerConfigurationReader reader = new StaxServerConfigurationReader();
			reader.read("/appsensor-server-rules-invalid-mp-window-config.xml", "/appsensor_server_config_2.0.xsd");
		}
		catch (ConfigurationException exception){
			assertTrue(exception.toString().startsWith("org.owasp.appsensor.core.exceptions.ConfigurationException: Incompatible windows set in rule: "));
			return;
		}
		fail();
	}

	@Test
	public void testInvalidRulesLoadDuplicateGuids() {
		try {
			ServerConfigurationReader reader = new StaxServerConfigurationReader();
			reader.read("/appsensor-server-rules-duplicate-mp-guids-config.xml", "/appsensor_server_config_2.0.xsd");
		}
		catch (ConfigurationException exception){
			assertTrue(exception.toString().startsWith("org.owasp.appsensor.core.exceptions.ConfigurationException: Repeated GUID discovered in Detection Point: "));
			return;
		}
		fail();
	}
}