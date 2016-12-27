package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import java.util.LinkedList;
import java.util.Queue;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.Interval;
import org.owasp.appsensor.core.rule.MonitorPoint;

public class TrimTest {
	static AggregateEventAnalysisEngine engine;
	static MonitorPoint point1;
	static Queue<Notification> queue;

	@BeforeClass
	public static void setUpOnce() {
		engine = new AggregateEventAnalysisEngine();
		point1 = new MonitorPoint(new DetectionPoint(DetectionPoint.Category.INPUT_VALIDATION, "IE1"), "1");
	}

	@Before
	public void setUpEach() {
		queue = buildQueue();
	}

	@Test
	public void testTrimOne() {
		DateTime trimTime = new DateTime(10);
		int lengthBefore = queue.size();

		engine.trim(queue, trimTime);

		assertEquals(lengthBefore - 1, queue.size());

		for (Notification ts : queue) {
			DateTime dt = ts.getStartTime();
			assertTrue(dt.isAfter(trimTime));
		}
	}

	@Test
	public void testTrimNone() {
		DateTime trimTime = new DateTime(9);
		int lengthBefore = queue.size();

		engine.trim(queue, trimTime);

		assertEquals(lengthBefore, queue.size());

		for (Notification ts : queue) {
			DateTime dt = ts.getStartTime();
			assertTrue(dt.isAfter(trimTime));
		}
	}

	@Test
	public void testTrimAll() {
		DateTime trimTime = new DateTime(14);

		engine.trim(queue, trimTime);

		assertEquals(0, queue.size());

		for (Notification ts : queue) {
			DateTime dt = ts.getStartTime();
			assertTrue(dt.isAfter(trimTime));
		}
	}

	private static Queue<Notification> buildQueue() {
		Queue<Notification> queue = new LinkedList<Notification>();

		queue.add(new Notification(2, Interval.MINUTES, new DateTime(10), point1));
		queue.add(new Notification(2, Interval.MINUTES, new DateTime(11), point1));
		queue.add(new Notification(2, Interval.MINUTES, new DateTime(12), point1));
		queue.add(new Notification(2, Interval.MINUTES, new DateTime(13), point1));
		queue.add(new Notification(2, Interval.MINUTES, new DateTime(14), point1));

		return queue;
	}

}
