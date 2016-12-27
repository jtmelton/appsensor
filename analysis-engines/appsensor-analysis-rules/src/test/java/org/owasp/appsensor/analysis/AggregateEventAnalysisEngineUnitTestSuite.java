package org.owasp.appsensor.analysis;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)

@Suite.SuiteClasses({
	   CheckClauseTest.class,
	   CheckExpressionTest.class,
	   CheckRuleTest.class,
	   GetQueueIntervalTest.class,
	   TrimTest.class
	})

public class AggregateEventAnalysisEngineUnitTestSuite {
}
