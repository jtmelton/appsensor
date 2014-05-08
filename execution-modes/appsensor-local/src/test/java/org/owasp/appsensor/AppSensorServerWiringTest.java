package org.owasp.appsensor;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations={"classpath:base-context.xml"})
public class AppSensorServerWiringTest {

	@Autowired
	private AppSensorServer appSensorServer;
	
	@Test
	public void testInstantiation() {
		assertNotNull("Server instance is null", appSensorServer);
		assertNotNull("Event store cannot is null", appSensorServer.getEventStore());
		System.err.println(appSensorServer.getEventStore().getClass());
		assertNotNull("Attack store cannot is null", appSensorServer.getAttackStore());
		assertNotNull("Response store cannot is null", appSensorServer.getResponseStore());
		assertNotNull("EventAnalysisEngine store cannot is null", appSensorServer.getEventAnalysisEngine());
		assertNotNull("AttackAnalysisEngine store cannot is null", appSensorServer.getAttackAnalysisEngine());
		assertNotNull("ClientApplicationIdentificationHeaderName cannot be null", appSensorServer.getConfiguration().getClientApplicationIdentificationHeaderName());
	}
}