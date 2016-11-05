package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CheckRuleTest {
	static AggregateEventAnalysisEngine engine;

	@BeforeClass
	public static void setUpOnce() {

	}

	@Before
	public void setUpEach() {
		engine = new AggregateEventAnalysisEngine();
	}

	@Test
	public void testAddRule() {
		engine.addRule(new Rule());
		assertEquals(1, engine.getRules().size());
	}

	@Test
	public void testClearRules() {
		engine.addRule(new Rule());
		Assume.assumeFalse(engine.getRules().isEmpty());
		engine.clearRules();
		assertEquals(0, engine.getRules().size());
	}

}