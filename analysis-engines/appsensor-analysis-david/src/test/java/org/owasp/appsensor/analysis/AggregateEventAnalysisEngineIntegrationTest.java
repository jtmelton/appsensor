package org.owasp.appsensor.analysis;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.Queue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.owasp.appsensor.core.Interval;

/**
 * Integration tests for AggregateEventAnalysisEngine
 *
 * SEE APPSENSOR-LOCAL TESTS
 *
 * @author David Scrobonia (davidscrobonia@gmail.com)
 */

public class AggregateEventAnalysisEngineIntegrationTest {
	AggregateEventAnalysisEngine engine;

	@Before
	public void setUp() throws Exception {
		engine = new AggregateEventAnalysisEngine();
	}

	@Test
	public void test() {

	}
}

