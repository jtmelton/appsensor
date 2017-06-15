package org.owasp.appsensor.storage.influxdb;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;

import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.owasp.appsensor.core.AppSensorClient;
import org.owasp.appsensor.core.AppSensorServer;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.rule.Rule;
import org.owasp.appsensor.local.analysis.SimpleAggregateEventAnalysisEngineTest;
import org.springframework.core.env.Environment;

/**
 * Test basic InfluxDb based * Store's by extending the ReferenceStatisticalEventAnalysisEngineTest
 * and only doing the file based setup. All of the same tests execute, but with the InfluxDb
 * based stores instead of the memory based stores.
 *
 * @author John Melton (jtmelton@gmail.com) http://www.jtmelton.com/
 */
public class InfluxDbEventStorageWithRulesTest extends SimpleAggregateEventAnalysisEngineTest {

	@Inject
	Environment environment;

	@Inject
	AppSensorServer appSensorServer;

	@Inject
	AppSensorClient appSensorClient;

    @Before
    public void checkInitialization() {
    	Assume.assumeTrue(isInitializedProperly());
    }

    @Test
    public void testAttackCreation() throws Exception {
    	if(! isInitializedProperly()) {
    		System.err.println("Test not running because environment variables are not setup properly.");
    	} else {
    		// add rules/detection points
    		ArrayList<Rule> rulesToAdd = new ArrayList<Rule>();
    		rulesToAdd.add(rules.get(0));
    		appSensorServer.getConfiguration().setRules(rulesToAdd);

    		// add detection point
    		ArrayList<DetectionPoint> dpsToAdd = new ArrayList<DetectionPoint>();
    		dpsToAdd.add(detectionPoints.get(0));
    		appSensorServer.getConfiguration().setDetectionPoints(dpsToAdd);

    		DetectionPoint detectionPoint1 = detectionPoints.get(0);

    		// get events and attacks
    		int numEvents = appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size();
    		int numDPAttacks = appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size();
    		int numRuleAttacks = appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size();

    		// useless sanity check
    		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
    		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
    		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

    		// 1 event
    		addEvent(bob, detectionPoint1);
    		numEvents++;

    		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
    		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
    		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

    		// 1 event
    		addEvent(bob, detectionPoint1);
    		numEvents++;

    		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
    		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
    		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

    		// Attack triggered on 3rd event
    		addEvent(bob, detectionPoint1);
    		numEvents++; numDPAttacks++; numRuleAttacks++;

    		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
    		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
    		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());

    		// 3 events and triggered attack on 6th event
    		addEvents(bob, detectionPoint1, 3);
    		numEvents += 3; numDPAttacks++; numRuleAttacks++;

    		assertEquals(numEvents, appSensorServer.getEventStore().findEvents(criteria.get("dp1")).size());
    		assertEquals(numDPAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("dp1")).size());
    		assertEquals(numRuleAttacks, appSensorServer.getAttackStore().findAttacks(criteria.get("rule1")).size());
    	}
    }

  private boolean isInitializedProperly() {
    return StringUtils.isNotBlank(environment.getProperty(Utils.INFLUXDB_CONNECTION_STRING)) &&
           StringUtils.isNotBlank(environment.getProperty(Utils.INFLUXDB_USERNAME)) &&
           StringUtils.isNotBlank(environment.getProperty(Utils.INFLUXDB_PASSWORD));
  }
}