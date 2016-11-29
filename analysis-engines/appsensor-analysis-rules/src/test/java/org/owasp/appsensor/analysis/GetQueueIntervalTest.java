package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

public class GetQueueIntervalTest {
	static AggregateEventAnalysisEngine engine;

	@BeforeClass
	public static void setUpOnce() {
		engine = new AggregateEventAnalysisEngine();
	}

	@Before
	public void setUpEach() {

	}

	@Ignore
	@Test
	public void test() {
		fail("Not yet implemented");
	}
}