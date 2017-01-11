package org.owasp.appsensor.analysis;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)

@Suite.SuiteClasses({
	   CheckClauseTest.class,
	   CheckExpressionTest.class,
	   TrimTest.class
	})

public class AggregateEventAnalysisEngineUnitTestSuite {
}
