package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.LinkedList;

import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;

public class CheckClauseTest {
	static AggregateEventAnalysisEngine engine;
	static RulesDetectionPoint point1, point2, point3;

	@BeforeClass
	public static void setUp() {
		engine = new AggregateEventAnalysisEngine();
		point1 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1"), "1");
		point2 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2"), "2");
		point3 = new RulesDetectionPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3"), "3");
	}

	@Test
	public void testExactMatchOneDetectionPoint() {
		ArrayList<RulesDetectionPoint> points = new ArrayList<RulesDetectionPoint>();
		points.add(point1);
		Clause clause = new Clause (new Interval(5, Interval.MINUTES), points);

		LinkedList<TriggeredSensor> sensors = new LinkedList<>();
		sensors.add(new TriggeredSensor(2, Interval.MINUTES, new DateTime(10), point1));

		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testExactMatchTwoDetectionPoints() {
		ArrayList<RulesDetectionPoint> points = new ArrayList<RulesDetectionPoint>();
		points.add(point1);
		points.add(point2);
		Clause clause = new Clause (new Interval(5, Interval.MINUTES), points);

		LinkedList<TriggeredSensor> sensors = new LinkedList<>();
		sensors.add(new TriggeredSensor(2, Interval.MINUTES, new DateTime(10), point1));
		sensors.add(new TriggeredSensor(3, Interval.MINUTES, new DateTime(10), point2));

		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testExtraDetectionPoints() {
		ArrayList<RulesDetectionPoint> points = new ArrayList<RulesDetectionPoint>();
		points.add(point1);
		Clause clause = new Clause (new Interval(5, Interval.MINUTES), points);

		LinkedList<TriggeredSensor> sensors = new LinkedList<>();
		sensors.add(new TriggeredSensor(2, Interval.MINUTES, new DateTime(10), point1));
		sensors.add(new TriggeredSensor(3, Interval.MINUTES, new DateTime(10), point2));

		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testNoDetectionPoints() {
		ArrayList<RulesDetectionPoint> points = new ArrayList<RulesDetectionPoint>();
		points.add(point1);
		Clause clause = new Clause (new Interval(5, Interval.MINUTES), points);

		LinkedList<TriggeredSensor> sensors = new LinkedList<>();

		assertFalse(engine.checkClause(clause, sensors));
	}

	@Test
	public void testMissingDetectionPoint() {
		ArrayList<RulesDetectionPoint> points = new ArrayList<RulesDetectionPoint>();
		points.add(point1);
		points.add(point2);
		Clause clause = new Clause (new Interval(5, Interval.MINUTES), points);

		LinkedList<TriggeredSensor> sensors = new LinkedList<>();
		sensors.add(new TriggeredSensor(2, Interval.MINUTES, new DateTime(10), point1));

		assertFalse(engine.checkClause(clause, sensors));
	}



}
