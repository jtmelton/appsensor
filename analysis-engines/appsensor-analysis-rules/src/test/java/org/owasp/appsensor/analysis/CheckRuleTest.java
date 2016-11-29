package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.appsensor.core.rule.Rule;

public class CheckRuleTest {
	static AggregateEventAnalysisEngine engine;

	@BeforeClass
	public static void setUpOnce() {

	}

	@Before
	public void setUpEach() {
		engine = new AggregateEventAnalysisEngine();
	}

}