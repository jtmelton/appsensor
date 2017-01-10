package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.LinkedList;

import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.rule.Clause;
import org.owasp.appsensor.core.rule.MonitorPoint;

public class CheckClauseTest {
	static AggregateEventAnalysisEngine engine;
	static MonitorPoint point1, point2, point3;

	@BeforeClass
	public static void setUp() {
		engine = new AggregateEventAnalysisEngine();
		point1 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1"), "1");
		point2 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE2"), "2");
		point3 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE3"), "3");
	}

	@Test
	public void testExactMatchOneDetectionPoint() {
		ArrayList<DetectionPoint> points = new ArrayList<DetectionPoint>();
		points.add(point1);
		Clause clause = new Clause(points);

		LinkedList<Notification> sensors = new LinkedList<>();
		sensors.add(new Notification(2, Interval.MINUTES, new DateTime(10), point1));

		System.out.println("FAILING");
		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testExactMatchTwoDetectionPoints() {
		ArrayList<DetectionPoint> points = new ArrayList<DetectionPoint>();
		points.add(point1);
		points.add(point2);
		Clause clause = new Clause (points);

		LinkedList<Notification> sensors = new LinkedList<>();
		sensors.add(new Notification(2, Interval.MINUTES, new DateTime(10), point1));
		sensors.add(new Notification(3, Interval.MINUTES, new DateTime(10), point2));

		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testExtraDetectionPoints() {
		ArrayList<DetectionPoint> points = new ArrayList<DetectionPoint>();
		points.add(point1);
		Clause clause = new Clause (points);

		LinkedList<Notification> sensors = new LinkedList<>();
		sensors.add(new Notification(2, Interval.MINUTES, new DateTime(10), point1));
		sensors.add(new Notification(3, Interval.MINUTES, new DateTime(10), point2));

		assertTrue(engine.checkClause(clause, sensors));
	}

	@Test
	public void testNoDetectionPoints() {
		ArrayList<DetectionPoint> points = new ArrayList<DetectionPoint>();
		points.add(point1);
		Clause clause = new Clause (points);

		LinkedList<Notification> sensors = new LinkedList<>();

		assertFalse(engine.checkClause(clause, sensors));
	}

	@Test
	public void testMissingDetectionPoint() {
		ArrayList<DetectionPoint> points = new ArrayList<DetectionPoint>();
		points.add(point1);
		points.add(point2);
		Clause clause = new Clause (points);

		LinkedList<Notification> sensors = new LinkedList<>();
		sensors.add(new Notification(2, Interval.MINUTES, new DateTime(10), point1));

		assertFalse(engine.checkClause(clause, sensors));
	}



}
